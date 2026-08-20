from typing import Any, Dict, List


class SentinelXSOCAgent:

    def __init__(self):
        self.name = "SentinelX SOC Agent"
        self.version = "1.0"

    def analyze(
        self,
        event: Dict[str, Any],
        detection: Dict[str, Any] | None = None,
        threat_intelligence: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:

        detection = detection or {}
        threat_intelligence = threat_intelligence or []

        verdict = str(
            detection.get(
                "verdict",
                "UNKNOWN"
            )
        ).upper()

        risk_score = int(
            detection.get(
                "risk_score",
                0
            )
        )

        severity = str(
            detection.get(
                "severity",
                "LOW"
            )
        ).upper()

        process_name = str(
            event.get(
                "process_name",
                "unknown"
            )
        )

        command_line = str(
            event.get(
                "command_line",
                ""
            )
        )

        source_ip = event.get(
            "source_ip"
        )

        destination_ip = event.get(
            "destination_ip"
        )

        reasoning = []

        recommendations = []

        mitre_technique = None

        if process_name.lower() == "powershell.exe":

            reasoning.append(
                "PowerShell execution was detected."
            )

            mitre_technique = "T1059.001"

            recommendations.extend([
                "Investigate the PowerShell command line.",
                "Check the parent process.",
                "Review the originating user.",
                "Search for related network connections."
            ])

        if "encodedcommand" in command_line.lower():

            reasoning.append(
                "Encoded PowerShell command detected, "
                "which can indicate command obfuscation."
            )

            recommendations.append(
                "Decode and analyze the PowerShell payload."
            )

        if destination_ip:

            reasoning.append(
                f"Network communication with "
                f"{destination_ip} was observed."
            )

            recommendations.append(
                f"Enrich and investigate destination IP "
                f"{destination_ip}."
            )

        if verdict == "MALICIOUS":

            reasoning.append(
                "The ML detection model classified "
                "the activity as malicious."
            )

        elif verdict == "BENIGN":

            reasoning.append(
                "The ML detection model classified "
                "the activity as benign."
            )

        if risk_score >= 80:

            severity = "CRITICAL"

            recommendations.extend([
                "Create a security incident.",
                "Isolate the affected endpoint if compromise "
                "is confirmed.",
                "Preserve forensic evidence."
            ])

        elif risk_score >= 60:

            severity = "HIGH"

            recommendations.append(
                "Investigate the endpoint and related events."
            )

        elif risk_score >= 40:

            severity = "MEDIUM"

            recommendations.append(
                "Continue monitoring for related activity."
            )

        else:

            severity = "LOW"

        if not reasoning:

            reasoning.append(
                "No significant suspicious behavior "
                "was identified by the available analysis."
            )

        if not recommendations:

            recommendations.append(
                "Continue monitoring the event."
            )

        return {
            "agent": self.name,
            "version": self.version,

            "verdict": verdict,

            "risk_score": risk_score,

            "severity": severity,

            "mitre_technique": mitre_technique,

            "summary": self._create_summary(
                verdict,
                severity,
                risk_score
            ),

            "reasoning": reasoning,

            "recommendations": recommendations,

            "event": event,

            "threat_intelligence": threat_intelligence,
        }

    def _create_summary(
        self,
        verdict: str,
        severity: str,
        risk_score: int
    ) -> str:

        if verdict == "MALICIOUS":

            return (
                f"SentinelX identified potentially malicious "
                f"activity with a risk score of {risk_score}/100 "
                f"and severity {severity}."
            )

        if verdict == "BENIGN":

            return (
                f"SentinelX classified the activity as benign "
                f"with a risk score of {risk_score}/100."
            )

        return (
            f"SentinelX could not determine the activity "
            f"with high confidence. Risk score: "
            f"{risk_score}/100."
        )
