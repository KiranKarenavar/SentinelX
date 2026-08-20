from app.integrations.wazuh import WazuhClient
from app.integrations.normalizer import normalize_wazuh_alert
from app.detection.engine import DetectionEngine
from app.detection.correlator import CorrelationEngine
from app.detection.scorer import calculate_score, calculate_severity


class DetectionPipeline:

    def __init__(self):

        self.wazuh = WazuhClient()

        self.detector = DetectionEngine()

        self.correlator = CorrelationEngine()

    def process_alert(self, alert: dict) -> dict:

        event = normalize_wazuh_alert(alert)

        detections = self.detector.evaluate(event)

        self.correlator.add_event(event)

        correlations = self.correlator.correlate()

        results = []

        for detection in detections:

            correlation_bonus = 10 if correlations else 0

            score = calculate_score(
                detection["severity"],
                ioc_score=0,
                correlation_bonus=correlation_bonus
            )

            severity = calculate_severity(score)

            results.append({
                "rule_id": detection["rule_id"],
                "rule_name": detection["rule_name"],
                "severity": severity,
                "score": score,
                "event": event
            })

        return {
            "event": event,
            "detections": results,
            "correlations": correlations
        }

    def run(self, limit: int = 20):

        alerts = self.wazuh.get_alerts(limit)

        alert_list = alerts.get("data", {}).get("affected_items", [])

        results = []

        for alert in alert_list:

            result = self.process_alert(alert)

            if result["detections"] or result["correlations"]:
                results.append(result)

        return results
