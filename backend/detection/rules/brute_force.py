from collections import Counter
from typing import Any


def detect_brute_force(
    events: list[dict[str, Any]],
    threshold: int = 5,
) -> list[dict[str, Any]]:
    """
    Detect repeated failed authentication attempts.

    A brute-force alert is generated when the same source
    IP produces at least `threshold` failed login events.
    """

    failed_attempts = Counter()

    for event in events:

        event_type = str(
            event.get("event_type", "")
        ).lower()

        status = str(
            event.get("status", "")
        ).lower()

        if (
            event_type in {
                "login",
                "authentication",
                "auth",
            }
            and status in {
                "failed",
                "failure",
                "denied",
            }
        ):
            src_ip = event.get("src_ip")

            if src_ip:
                failed_attempts[src_ip] += 1

    detections = []

    for src_ip, count in failed_attempts.items():

        if count >= threshold:

            detections.append(
                {
                    "detection_type": "BRUTE_FORCE",
                    "source_ip": src_ip,
                    "attempts": count,
                    "severity": "HIGH",
                    "description": (
                        f"Possible brute-force attack "
                        f"from {src_ip}: "
                        f"{count} failed login attempts"
                    ),
                }
            )

    return detections
