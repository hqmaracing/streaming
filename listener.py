import csv
import socket
import time
import traceback
from datetime import datetime
from io import StringIO

TCP_IP = "192.168.12.101"
TCP_PORT = 50000
LOG_FILE = "raw_packets.log"
RECONNECT_DELAY_SECONDS = 2
FINISH_GRACE_SECONDS = 15


# ---------------------------------------------------------------------------
# Low-level parsing helpers
# ---------------------------------------------------------------------------

def _to_int(value):
    """Return int(value) when possible, otherwise None."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _is_numeric_value(value):
    return str(value or "").strip().isdigit()


def _parse_csv_line(line):
    """Parse a single incoming stream line that uses CSV-like formatting.

    Example input:
      $A,"1","1",14287310,"Mallory","Detwiler","",1
    """
    raw = line.strip()
    if not raw:
        return None, []

    try:
        row = next(csv.reader(StringIO(raw), skipinitialspace=True))
    except Exception:
        # Keep parser permissive; unknown/bad rows should not crash listener.
        return None, []

    if not row:
        return None, []

    return row[0].strip(), [col.strip() for col in row[1:]]


def _parse_duration_to_seconds(value):
    """Parse HH:MM:SS(.mmm) duration-like text into seconds."""
    if not value:
        return None

    text = str(value).strip().replace('"', '')
    parts = text.split(":")
    if len(parts) != 3:
        return None

    hours = _to_int(parts[0])
    minutes = _to_int(parts[1])
    if hours is None or minutes is None:
        return None

    try:
        seconds = float(parts[2])
    except ValueError:
        return None

    return (hours * 3600) + (minutes * 60) + seconds


def _is_finish_flag(value):
    return "finish" in str(value or "").strip().lower()


# ---------------------------------------------------------------------------
# Session / driver state helpers
# ---------------------------------------------------------------------------

def _new_session_state():
    return {
        "race": {
            "packet": None,          # $B field[0] unknown numeric value
            "title": "",            # $B field[1], e.g. "A Feature 1"
            "started_at": None,
        },
        "class": {
            "name": "",             # from $C,* line that looks like class
            "unknown": {},           # keep any extra $C values for debugging
        },
        "track": {
            "name": "",             # from $E,"TRACKNAME",...
            "length": "",           # from $E,"TRACKLENGTH",...
            "extra": {},
        },
        "clock": {
            "laps_to_go": None,      # from $F field[0]
            "unknown_time": "",     # from $F field[1] (unknown meaning)
            "time_of_day": "",      # from $F field[2], appears wall clock
            "elapsed": "",          # from $F field[3], session elapsed
            "flag": "",             # from $F field[4]
        },
        "finish": {
            "started_at": None,
            "leader_laps": None,
        },
        # drivers keyed by numeric short code/id.
        "drivers": {},
        # index by car/slot number to help resolve $G/$H/$J mismatches.
        "driver_index": {},
        # live running positions keyed by code
        "positions": {},
        # fastest-lap data keyed by code
        "fastest": {},
        "raw_last_by_type": {},
    }


def _upsert_driver(session, code, car_number=None, first_name="", last_name="", transponder=None, extra=None):
    key = str(code).strip()
    if not key:
        return None

    drivers = session["drivers"]
    driver = drivers.get(key) or {
        "code": key,
        "car": car_number or key,
        "first_name": "",
        "last_name": "",
        "transponder": None,
        "extra": {},
    }

    if car_number:
        driver["car"] = str(car_number)
    if first_name:
        driver["first_name"] = first_name
    if last_name:
        driver["last_name"] = last_name
    if transponder is not None:
        driver["transponder"] = transponder
    if isinstance(extra, dict):
        driver["extra"].update(extra)

    drivers[key] = driver

    # Track by car/slot as secondary lookup.
    if driver.get("car"):
        session["driver_index"][str(driver["car"])] = key

    return key


def _resolve_driver_key(session, incoming_code):
    """Resolve incoming code to known driver key.

    Stream sometimes sends numeric strings, sometimes initials.
    We try direct key first, then car/slot index.
    """
    code = str(incoming_code).strip()
    if code in session["drivers"]:
        return code
    return session["driver_index"].get(code, code)


def _current_leader_laps(session):
    leader_pos = _current_leader_position(session)
    return leader_pos.get("laps_completed") if leader_pos else None


def _current_leader_position(session):
    positions = list(session["positions"].values())
    if not positions:
        return None

    return min(
        positions,
        key=lambda p: (
            -(p.get("laps_completed") if p.get("laps_completed") is not None else -1),
            p.get("elapsed_seconds") if p.get("elapsed_seconds") is not None else float("inf"),
        ),
    )


def _build_leaderboard(session):
    positions = session["positions"]
    if not positions:
        return []

    rows = []
    for code, pos_data in positions.items():
        driver = session["drivers"].get(
            code,
            {"code": code, "car": code, "first_name": "", "last_name": ""},
        )
        fastest = session["fastest"].get(code, {})

        rows.append(
            {
                "official_pos": pos_data.get("position"),
                "car": driver.get("car") or code,
                "code": code,
                "name": code,
                "first_name": driver.get("first_name") or "",
                "last_name": driver.get("last_name") or "",
                "laps": pos_data.get("laps_completed"),
                "elapsed": pos_data.get("elapsed"),
                "elapsed_seconds": pos_data.get("elapsed_seconds"),
                "seen_at_leader_lap": pos_data.get("seen_at_leader_lap"),
                "last_g_at": pos_data.get("last_g_at"),
                "display_gap_seconds": pos_data.get("display_gap_seconds"),
                "best_lap": fastest.get("best_lap"),
                "best_lap_lap": fastest.get("lap_number"),
            }
        )

    rows.sort(
        key=lambda r: (
            -(r["laps"] if r["laps"] is not None else -1),
            r["elapsed_seconds"] if r["elapsed_seconds"] is not None else float("inf"),
            r["official_pos"] if r["official_pos"] is not None else 999,
            r["car"],
        )
    )
    for idx, row in enumerate(rows, start=1):
        row["pos"] = idx

    finish_state = session.get("finish", {})
    finish_started_at = finish_state.get("started_at")
    finish_leader_laps = finish_state.get("leader_laps")
    finish_grace_expired = (
        finish_started_at is not None
        and (time.monotonic() - finish_started_at) >= FINISH_GRACE_SECONDS
    )

    leader_laps = rows[0].get("laps") if rows else None
    for row in rows:
        confirmed_laps_down = 0
        if (
            row["pos"] != 1
            and leader_laps is not None
            and row.get("laps") is not None
        ):
            raw_lap_diff = leader_laps - row["laps"]
            if raw_lap_diff > 0:
                confirmed_laps_down = max(0, raw_lap_diff - 1)
                if row.get("seen_at_leader_lap") == leader_laps:
                    confirmed_laps_down += 1

        if (
            finish_grace_expired
            and row["pos"] != 1
            and finish_leader_laps is not None
            and row.get("laps") is not None
        ):
            final_raw_lap_diff = finish_leader_laps - row["laps"]
            crossed_after_finish = (
                row.get("last_g_at") is not None
                and finish_started_at is not None
                and row["last_g_at"] > finish_started_at
            )
            if final_raw_lap_diff > 0 and not crossed_after_finish:
                confirmed_laps_down = max(confirmed_laps_down, final_raw_lap_diff)

        if confirmed_laps_down > 0:
            row["gap"] = f"-{confirmed_laps_down}L"
        elif row["pos"] == 1:
            row["gap"] = ""
        elif row.get("display_gap_seconds") is None:
            row["gap"] = ""
        else:
            row["gap"] = f"{row['display_gap_seconds']:.3f}"

        # Keep legacy keys so existing overlay markup still works.
        row["last"] = row.get("best_lap") or ""

    return rows


# ---------------------------------------------------------------------------
# Packet handlers by line type
# ---------------------------------------------------------------------------

def _handle_line(session, line_type, fields, shared_state):
    session["raw_last_by_type"][line_type] = fields

    if line_type == "$B":
        # New race/session marker.
        session["race"]["packet"] = fields[0] if len(fields) >= 1 else None
        session["race"]["title"] = fields[1] if len(fields) >= 2 else ""
        session["race"]["started_at"] = datetime.now().isoformat(timespec="seconds")

        # Clear line-by-line race data while keeping track/class data available.
        session["drivers"] = {}
        session["driver_index"] = {}
        session["positions"] = {}
        session["fastest"] = {}
        session["finish"] = {"started_at": None, "leader_laps": None}

    elif line_type == "$A":
        # Expected: code, car, transponder, first, last, blank, unknown
        code = fields[0] if len(fields) >= 1 else ""
        car = fields[1] if len(fields) >= 2 else code
        if _is_numeric_value(code) and _is_numeric_value(car):
            transponder = _to_int(fields[2]) if len(fields) >= 3 else None
            first = fields[3] if len(fields) >= 4 else ""
            last = fields[4] if len(fields) >= 5 else ""
            unknown_tail = fields[5:] if len(fields) > 5 else []

            _upsert_driver(
                session,
                code=code,
                car_number=car,
                first_name=first,
                last_name=last,
                transponder=transponder,
                extra={"from": "$A", "unknown_tail": unknown_tail},
            )

    elif line_type == "$COMP":
        # Similar to $A; use it to enrich/repair driver fields.
        code = fields[0] if len(fields) >= 1 else ""
        car = fields[1] if len(fields) >= 2 else code
        if _is_numeric_value(code) and _is_numeric_value(car):
            first = fields[3] if len(fields) >= 4 else ""
            last = fields[4] if len(fields) >= 5 else ""

            _upsert_driver(
                session,
                code=code,
                car_number=car,
                first_name=first,
                last_name=last,
                extra={"from": "$COMP", "raw": fields},
            )

    elif line_type == "$C":
        key = fields[0] if len(fields) >= 1 else ""
        value = fields[1] if len(fields) >= 2 else ""

        # Assign the class name, ie. Senior Honda
        session["class"]["name"] = value
        

    elif line_type == "$E":
        meta_key = fields[0] if len(fields) >= 1 else ""
        meta_value = fields[1] if len(fields) >= 2 else ""

        if meta_key == "TRACKNAME":
            session["track"]["name"] = meta_value
        elif meta_key == "TRACKLENGTH":
            session["track"]["length"] = meta_value
        else:
            session["track"]["extra"][meta_key] = meta_value

    elif line_type == "$F":
        session["clock"]["laps_to_go"] = _to_int(fields[0]) if len(fields) >= 1 else None
        session["clock"]["unknown_time"] = fields[1] if len(fields) >= 2 else ""
        session["clock"]["time_of_day"] = fields[2] if len(fields) >= 3 else ""
        session["clock"]["elapsed"] = fields[3] if len(fields) >= 4 else ""
        session["clock"]["flag"] = fields[4] if len(fields) >= 5 else ""

        if _is_finish_flag(session["clock"]["flag"]):
            if session["finish"]["started_at"] is None:
                session["finish"]["started_at"] = time.monotonic()
                session["finish"]["leader_laps"] = _current_leader_laps(session)
        else:
            session["finish"] = {"started_at": None, "leader_laps": None}

    elif line_type == "$G":
        # Expected: position, code, laps_completed, elapsed
        position = _to_int(fields[0]) if len(fields) >= 1 else None
        raw_code = fields[1] if len(fields) >= 2 else ""
        laps_completed = _to_int(fields[2]) if len(fields) >= 3 else None
        elapsed = fields[3] if len(fields) >= 4 else ""
        elapsed_seconds = _parse_duration_to_seconds(elapsed)

        # Some feeds leave laps blank until a driver completes their first lap.
        # Treat that as 0 so stalled/non-scoring cars can still be marked laps down.
        if laps_completed is None:
            laps_completed = 0

        driver_key = _resolve_driver_key(session, raw_code)

        if driver_key not in session["drivers"] and _is_numeric_value(driver_key):
            _upsert_driver(session, code=driver_key, car_number=driver_key)

        if driver_key in session["drivers"]:
            existing_pos = session["positions"].get(driver_key, {})
            leader_pos = _current_leader_position(session)
            leader_laps = laps_completed if position == 1 else _current_leader_laps(session)
            display_gap_seconds = existing_pos.get("display_gap_seconds")

            if position == 1:
                display_gap_seconds = 0.0
            elif (
                leader_pos is not None
                and leader_laps is not None
                and laps_completed == leader_laps
                and leader_pos.get("elapsed_seconds") is not None
                and elapsed_seconds is not None
            ):
                display_gap_seconds = max(0.0, elapsed_seconds - leader_pos["elapsed_seconds"])

            session["positions"][driver_key] = {
                "position": position,
                "laps_completed": laps_completed,
                "elapsed": elapsed,
                "elapsed_seconds": elapsed_seconds,
                "seen_at_leader_lap": leader_laps,
                "last_g_at": time.monotonic(),
                "display_gap_seconds": display_gap_seconds,
            }

    elif line_type == "$H":
        # Expected: Fast Time Position, code, best_lap_number, best_lap_time
        fast_time_pos = fields[0]  #Currently unused put added for clarity on what that field is.
        raw_code = fields[1] if len(fields) >= 2 else ""
        lap_number = _to_int(fields[2]) if len(fields) >= 3 else None
        best_lap = fields[3] if len(fields) >= 4 else ""

        driver_key = _resolve_driver_key(session, raw_code)
        fastest = session["fastest"].get(driver_key, {})
        fastest.update({"lap_number": lap_number, "best_lap": best_lap})
        session["fastest"][driver_key] = fastest

    elif line_type == "$J":
        # Expected: code, best_lap_time, elapsed
        raw_code = fields[0] if len(fields) >= 1 else ""
        best_lap = fields[1] if len(fields) >= 2 else ""
        elapsed = fields[2] if len(fields) >= 3 else ""

        driver_key = _resolve_driver_key(session, raw_code)
        fastest = session["fastest"].get(driver_key, {})
        fastest.update({"best_lap": best_lap, "elapsed_when_set": elapsed})
        session["fastest"][driver_key] = fastest

    # Rebuild API-facing state after every line so overlay can update quickly.
    leaderboard = _build_leaderboard(session)
    shared_state.update(
        {
            "event_name": session["race"]["title"] or "",
            "session_name": session["class"]["name"] or "",
            "track_status": session["clock"]["flag"] or "",
            "laps_remaining": session["clock"]["laps_to_go"],
            "leaders": leaderboard[:5],
            "rest": leaderboard[5:10],
            # Rich debug data for future overlay changes.
            "session": {
                "race": session["race"],
                "class": session["class"],
                "track": session["track"],
                "clock": session["clock"],
            },
            "drivers": session["drivers"],
            "positions": session["positions"],
            "fastest": session["fastest"],
            "leaderboard": leaderboard,
        }
    )


def start_listener(shared_state):
    print("STARTING LISTENER")

    # Keep parser state across socket chunks.
    line_buffer = ""
    session = _new_session_state()

    while True:
        sock = None
        try:
            shared_state["listener_status"] = "connecting"
            shared_state["listener_error"] = None

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((TCP_IP, TCP_PORT))

            sock.settimeout(None)
            sock.sendall(b"\n")
            shared_state["listener_status"] = "connected"

            with open(LOG_FILE, "a", encoding="utf-8") as log:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        shared_state["listener_status"] = "disconnected"
                        break

                    ts = datetime.now().isoformat(timespec="seconds")
                    decoded = data.decode("utf-8", errors="replace")

                    shared_state["last_packet"] = {
                        "timestamp": ts,
                        "from": f"{TCP_IP}:{TCP_PORT}",
                        "byte_length": len(data),
                        "raw_utf8": decoded,
                        "raw_hex": data.hex(),
                    }

                    log.write(
                        f"\n[{ts}] from={TCP_IP}:{TCP_PORT} bytes={len(data)}"
                        f"\nutf8:\n{decoded}\nhex:\n{data.hex()}\n"
                    )
                    log.flush()

                    line_buffer += decoded
                    # Stream may contain blank lines between messages.
                    line_buffer = line_buffer.replace("\r", "")

                    while "\n" in line_buffer:
                        raw_line, line_buffer = line_buffer.split("\n", 1)
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue

                        line_type, fields = _parse_csv_line(raw_line)
                        if not line_type:
                            continue

                        _handle_line(session, line_type, fields, shared_state)

        except Exception as e:
            shared_state["listener_status"] = "error"
            shared_state["listener_error"] = str(e)
            print("LISTENER CRASHED:", e)
            traceback.print_exc()
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

            time.sleep(RECONNECT_DELAY_SECONDS)
