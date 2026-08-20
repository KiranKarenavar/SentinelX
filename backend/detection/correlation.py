from collections import defaultdict
from typing import Any


def correlate_detections(
    detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Correlate detections sharing the same IOC,
    source IP, or process.
    """

    groups = defaultdict(list)

    for detection in detections:

        key = (
            detection.get("source_ip")
            or detection.get("process")
            or detection.get("detection_type")
        )

        groups[key].append(detection)

    correlated = []

    for key, items in groups.items():

        if len(items) >= 2:

            correlated.append(
                {
                    "correlation_key": key,
                    "detection_count": len(items),
                    "detections": items,
                    "severity": "CRITICAL",
                    "description": (
                        f"Multiple security detections "
                        f"correlated around {key}"
                    ),
                }
            )

    return correlated
