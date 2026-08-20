from typing import Any


def detect_malicious_ip(
    event: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect IP addresses that are already known
    to be malicious by SentinelX intelligence.
    """

    src_ip = event.get("src_ip")

    if not src_ip:
        return []

    intelligence = event.get(
        "threat_intelligence",
        {},
    )

    malicious = intelligence.get(
        "malicious",
        False,
    )

    if not malicious:
        return []

    confidence = intelligence.get(
        "confidence",
        0,
    )

    return [
        {
            "detection_type": "MALICIOUS_IP",
            "source_ip": src_ip,
            "confidence": confidence,
            "severity": "CRITICAL",
            "description": (
                f"Known malicious IP detected: "
                f"{src_ip}"
            ),
        }
    ]
