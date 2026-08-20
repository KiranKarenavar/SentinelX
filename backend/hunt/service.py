import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()


WAZUH_ALERT_FILE = Path(
    os.getenv(
        "WAZUH_ALERT_FILE",
        "/var/ossec/logs/alerts/alerts.json",
    )
)


class ThreatHuntingService:
    """
    SentinelX threat hunting service.

    Searches an IOC across multiple security data sources.
    """

    def __init__(self):
        self.wazuh_alert_file = WAZUH_ALERT_FILE

    def search_wazuh(
        self,
        query: str,
    ) -> dict[str, Any]:
        """
        Search Wazuh local alert JSON for the IOC.
        """

        result = {
            "source": "Wazuh",
            "events": 0,
            "matches": [],
        }

        if not self.wazuh_alert_file.exists():
            result["error"] = (
                f"Wazuh alert file not found: "
                f"{self.wazuh_alert_file}"
            )
            return result

        try:
            with self.wazuh_alert_file.open(
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:

                for line in file:

                    if not line.strip():
                        continue

                    if query.lower() not in line.lower():
                        continue

                    try:
                        alert = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    result["events"] += 1

                    if len(result["matches"]) < 10:
                        result["matches"].append(alert)

        except PermissionError:
            result["error"] = (
                "Permission denied reading Wazuh alerts. "
                "Add the SentinelX user to the wazuh group."
            )

        except Exception as exc:
            result["error"] = str(exc)

        return result

    def search_threat_intelligence(
        self,
        query: str,
    ) -> dict[str, Any]:
        """
        Search SentinelX threat intelligence.

        Database integration will use PostgreSQL when the
        required database module/table is available.
        """

        return {
            "source": "Threat Intelligence",
            "events": 0,
            "matches": [],
            "status": "not_connected",
        }

    def search_honeypot(
        self,
        query: str,
    ) -> dict[str, Any]:
        """
        Search honeypot events.
        """

        return {
            "source": "Honeypot",
            "events": 0,
            "matches": [],
            "status": "not_connected",
        }

    def search_dns(
        self,
        query: str,
    ) -> dict[str, Any]:
        """
        Search DNS events.
        """

        return {
            "source": "DNS",
            "events": 0,
            "matches": [],
            "status": "not_connected",
        }

    def search_firewall(
        self,
        query: str,
    ) -> dict[str, Any]:
        """
        Search firewall events.
        """

        return {
            "source": "Firewall",
            "events": 0,
            "matches": [],
            "status": "not_connected",
        }

    def search_endpoint(
        self,
        query: str,
    ) -> dict[str, Any]:
        """
        Search endpoint events.
        """

        return {
            "source": "Endpoint",
            "events": 0,
            "matches": [],
            "status": "not_connected",
        }

    def calculate_verdict(
        self,
        results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Calculate a basic hunting risk verdict.
        """

        total_events = sum(
            result.get("events", 0)
            for result in results
        )

        malicious_intel = False

        for result in results:

            if result.get("source") == "Threat Intelligence":

                if result.get("malicious") is True:
                    malicious_intel = True

        if malicious_intel:
            verdict = "CRITICAL"
            score = 90

        elif total_events >= 10:
            verdict = "HIGH"
            score = 75

        elif total_events >= 5:
            verdict = "MEDIUM"
            score = 55

        elif total_events > 0:
            verdict = "LOW"
            score = 30

        else:
            verdict = "INFORMATIONAL"
            score = 0

        return {
            "risk_score": score,
            "verdict": verdict,
            "total_events": total_events,
        }

    async def hunt(
        self,
        query: str,
    ) -> dict[str, Any]:
        """
        Search the IOC across SentinelX security sources.
        """

        query = query.strip()

        if not query:
            raise ValueError(
                "Hunting query cannot be empty"
            )

        results = [
            self.search_wazuh(query),
            self.search_threat_intelligence(query),
            self.search_honeypot(query),
            self.search_dns(query),
            self.search_firewall(query),
            self.search_endpoint(query),
        ]

        verdict = self.calculate_verdict(
            results
        )

        return {
            "query": query,
            "sources": results,
            "verdict": verdict,
        }
