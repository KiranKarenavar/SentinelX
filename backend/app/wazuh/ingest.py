import json
import os
from typing import Optional


WAZUH_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"


class WazuhAlertIngestor:
    def __init__(self, alerts_file: str = WAZUH_ALERTS_FILE):
        self.alerts_file = alerts_file

    def read_alerts(self, limit: int = 20):
        """
        Read the latest Wazuh alerts from alerts.json.
        """

        if not os.path.exists(self.alerts_file):
            raise FileNotFoundError(
                f"Wazuh alerts file not found: {self.alerts_file}"
            )

        alerts = []

        with open(self.alerts_file, "r", encoding="utf-8") as file:
            lines = file.readlines()

        for line in lines[-limit:]:
            line = line.strip()

            if not line:
                continue

            try:
                alert = json.loads(line)
                alerts.append(alert)

            except json.JSONDecodeError:
                continue

        return alerts

    def normalize_alert(self, alert: dict) -> dict:
        """
        Convert a Wazuh alert into a SentinelX-friendly structure.
        """

        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        manager = alert.get("manager", {})

        normalized = {
            "timestamp": alert.get("timestamp"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level", 0),
            "rule_description": rule.get("description"),

            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "agent_ip": agent.get("ip"),

            "manager_name": manager.get("name"),

            "decoder": alert.get("decoder", {}).get("name"),

            "location": alert.get("location"),

            "full_log": alert.get("full_log"),

            "raw_alert": alert
        }

        return normalized

    def get_normalized_alerts(self, limit: int = 20):
        """
        Read and normalize the latest Wazuh alerts.
        """

        alerts = self.read_alerts(limit)

        return [
            self.normalize_alert(alert)
            for alert in alerts
        ]


if __name__ == "__main__":
    ingestor = WazuhAlertIngestor()

    print("=" * 70)
    print("SENTINELX WAZUH ALERT INGESTION TEST")
    print("=" * 70)

    try:
        alerts = ingestor.get_normalized_alerts(limit=5)

        print(f"\nAlerts found: {len(alerts)}")

        for index, alert in enumerate(alerts, start=1):
            print("\n" + "-" * 70)
            print(f"ALERT #{index}")
            print("-" * 70)

            print(json.dumps(alert, indent=2))

    except Exception as error:
        print(f"\nERROR: {error}")
