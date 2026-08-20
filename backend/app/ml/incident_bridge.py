from typing import Any, Dict

from app.ml.predictor import ThreatPredictor
from app.incidents.storage import create_incident


class MLIncidentBridge:

    def __init__(self):
        self.predictor = ThreatPredictor()

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:

        features = {
            "connection_count": event.get(
                "connection_count", 0
            ),

            "failed_logins": event.get(
                "failed_logins", 0
            ),

            "suspicious_port": event.get(
                "suspicious_port", 0
            ),

            "known_bad_ip": event.get(
                "known_bad_ip", 0
            ),

            "encoded_command": event.get(
                "encoded_command", 0
            ),

            "privilege_escalation": event.get(
                "privilege_escalation", 0
            ),
        }

        prediction = self.predictor.predict(features)

        return {
            "event": event,
            "prediction": prediction,
        }
