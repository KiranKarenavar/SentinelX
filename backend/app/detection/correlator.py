from datetime import datetime, timedelta


class CorrelationEngine:

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.events = []

    def add_event(self, event: dict) -> None:
        event["timestamp"] = event.get(
            "timestamp",
            datetime.utcnow().isoformat()
        )

        self.events.append(event)
        self._cleanup()

    def _cleanup(self):
        cutoff = datetime.utcnow() - timedelta(
            seconds=self.window_seconds
        )

        cleaned = []

        for event in self.events:
            try:
                timestamp = datetime.fromisoformat(
                    event["timestamp"]
                )

                if timestamp >= cutoff:
                    cleaned.append(event)

            except (ValueError, TypeError):
                cleaned.append(event)

        self.events = cleaned

    def correlate(self) -> list[dict]:

        correlations = []

        powershell_events = [
            e for e in self.events
            if e.get("process_name", "").lower()
            in ["powershell.exe", "pwsh.exe"]
        ]

        network_events = [
            e for e in self.events
            if e.get("event_type") == "network_connection"
        ]

        if powershell_events and network_events:

            correlations.append({
                "correlation_id": "CORR-001",
                "name": "PowerShell Network Activity",
                "severity": "HIGH",
                "description": (
                    "PowerShell execution followed by "
                    "network activity within the correlation window."
                ),
                "events": (
                    powershell_events + network_events
                )
            })

        return correlations
