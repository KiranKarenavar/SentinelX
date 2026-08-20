import json
from pathlib import Path
from typing import Any


def parse_cowrie_line(line: str) -> dict[str, Any] | None:
    """Parse one Cowrie JSON log line."""

    line = line.strip()

    if not line:
        return None

    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    return {
        "event_id": event.get("eventid"),
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "session": event.get("session"),
        "username": event.get("username"),
        "password": event.get("password"),
        "input": event.get("input"),
        "message": event.get("message"),
        "raw_event": event,
    }


def read_cowrie_log(log_path: str) -> list[dict[str, Any]]:
    """Read all valid Cowrie events from a JSON log file."""

    path = Path(log_path)

    if not path.exists():
        raise FileNotFoundError(f"Cowrie log not found: {log_path}")

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            event = parse_cowrie_line(line)

            if event:
                events.append(event)

    return events

import ipaddress


def extract_iocs(events: list[dict[str, Any]]) -> list[str]:
    """Extract unique IP addresses from Cowrie events."""

    iocs = set()

    for event in events:
        src_ip = event.get("src_ip")

        if not src_ip:
            continue

        try:
            ipaddress.ip_address(src_ip)
            iocs.add(src_ip)
        except ValueError:
            continue

    return sorted(iocs)
