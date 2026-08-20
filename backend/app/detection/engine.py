from typing import Any

from app.detection.rules import DETECTION_RULES


class DetectionEngine:

    def __init__(self):
        self.rules = DETECTION_RULES

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        detections = []

        for rule in self.rules:

            if rule["event_type"] != event.get("event_type"):
                continue

            conditions = rule.get("conditions", {})

            matched = False

            process_name = str(
                event.get("process_name", "")
            ).lower()

            command_line = str(
                event.get("command_line", "")
            ).lower()

            process_names = [
                x.lower()
                for x in conditions.get("process_names", [])
            ]

            if process_name in process_names:
                matched = True

            for keyword in conditions.get("keywords", []):
                if keyword.lower() in command_line:
                    matched = True

            if conditions.get("suspicious") is True:
                if event.get("suspicious") is True:
                    matched = True

            if matched:
                detections.append({
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "event": event
                })

        return detections
