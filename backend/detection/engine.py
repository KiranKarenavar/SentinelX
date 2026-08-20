from typing import Any

from detection.correlation import (
    correlate_detections,
)

from detection.rules.brute_force import (
    detect_brute_force,
)

from detection.rules.suspicious_process import (
    detect_suspicious_process,
)

from detection.rules.malicious_ip import (
    detect_malicious_ip,
)

from detection.rules.phishing import (
    detect_phishing,
)


class DetectionEngine:
    """
    SentinelX detection engine.

    Processes security events and applies
    multiple detection rules.
    """

    def analyze_events(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:

        detections = []

        # Brute-force detection
        detections.extend(
            detect_brute_force(events)
        )

        # Analyze each event
        for event in events:

            detections.extend(
                detect_suspicious_process(
                    event
                )
            )

            detections.extend(
                detect_malicious_ip(
                    event
                )
            )

            if event.get("event_type") == "email":

                detections.extend(
                    detect_phishing(event)
                )

        # Correlation
        correlated = correlate_detections(
            detections
        )

        return {
            "total_events": len(events),
            "detections": detections,
            "correlated_detections": correlated,
            "detection_count": len(detections),
            "correlation_count": len(correlated),
        }
