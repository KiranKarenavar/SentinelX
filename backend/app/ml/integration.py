from typing import Any, Dict

from app.ml.predictor import ThreatPredictor
from app.incidents.storage import create_incident


class MLEventAnalyzer:

    def __init__(self):

        self.predictor = ThreatPredictor()

    def _build_features(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, int]:

        command_line = str(
            event.get(
                "command_line",
                event.get(
                    "payload",
                    "",
                ),
            )
            or ""
        )

        process_name = str(
            event.get(
                "process_name",
                "",
            )
            or ""
        ).lower()

        failed_logins = event.get(
            "failed_logins",
            event.get(
                "failed_login",
                0,
            ),
        )

        try:
            failed_logins = int(
                failed_logins
            )
        except (
            TypeError,
            ValueError,
        ):
            failed_logins = 0

        connection_count = event.get(
            "connection_count",
            0,
        )

        try:
            connection_count = int(
                connection_count
            )
        except (
            TypeError,
            ValueError,
        ):
            connection_count = 0

        destination_port = event.get(
            "destination_port",
            event.get(
                "dest_port",
                0,
            ),
        )

        try:
            destination_port = int(
                destination_port
            )
        except (
            TypeError,
            ValueError,
        ):
            destination_port = 0

        suspicious_ports = {
            21,
            23,
            445,
            3389,
            4444,
            5555,
            8080,
        }

        suspicious_port = int(
            destination_port
            in suspicious_ports
        )

        known_bad_ip = int(
            bool(
                event.get(
                    "known_bad_ip",
                    event.get(
                        "suspicious_ip",
                        event.get(
                            "ioc_malicious",
                            False,
                        ),
                    ),
                )
            )
        )

        encoded_command = int(
            (
                "-encodedcommand"
                in command_line.lower()
            )
            or (
                "frombase64string"
                in command_line.lower()
            )
            or (
                "encoded"
                in command_line.lower()
            )
        )

        privilege_escalation = int(
            bool(
                event.get(
                    "privilege_escalation",
                    False,
                )
            )
        )

        if (
            process_name
            in {
                "powershell.exe",
                "powershell",
                "wscript.exe",
                "cscript.exe",
                "rundll32.exe",
            }
        ):
            encoded_command = max(
                encoded_command,
                int(
                    len(command_line) > 80
                ),
            )

        return {
            "connection_count":
                connection_count,

            "failed_logins":
                failed_logins,

            "suspicious_port":
                suspicious_port,

            "known_bad_ip":
                known_bad_ip,

            "encoded_command":
                encoded_command,

            "privilege_escalation":
                privilege_escalation,
        }

    def analyze(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        features = self._build_features(
            event
        )

        result = self.predictor.predict(
            features
        )

        prediction = str(
            result.get(
                "prediction",
                "BENIGN",
            )
        ).upper()

        confidence = float(
            result.get(
                "confidence",
                0.0,
            )
        )

        if prediction == "MALICIOUS":

            risk_score = max(
                80,
                int(
                    confidence * 100
                ),
            )

            if features[
                "known_bad_ip"
            ]:
                risk_score += 5

            if features[
                "encoded_command"
            ]:
                risk_score += 5

            if features[
                "privilege_escalation"
            ]:
                risk_score += 5

            risk_score = min(
                risk_score,
                100,
            )

        elif prediction == "SUSPICIOUS":

            risk_score = max(
                50,
                int(
                    confidence * 100
                ),
            )

        else:

            risk_score = min(
                30,
                int(
                    confidence * 100
                ),
            )

        if risk_score >= 90:
            severity = "CRITICAL"

        elif risk_score >= 70:
            severity = "HIGH"

        elif risk_score >= 40:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        return {
            "prediction": prediction,

            "confidence": round(
                confidence,
                4,
            ),

            "risk_score": risk_score,

            "severity": severity,

            "probabilities":
                result.get(
                    "probabilities",
                    {},
                ),

            "features": features,
        }


def calculate_risk_score(
    prediction: str,
    confidence: float,
    features: Dict[str, Any],
) -> int:

    prediction = str(
        prediction
    ).upper()

    confidence = float(
        confidence
    )

    score = int(
        confidence * 100
    )

    if prediction == "MALICIOUS":

        score = max(
            score,
            80,
        )

        if features.get(
            "known_bad_ip",
            0,
        ):
            score += 5

        if features.get(
            "encoded_command",
            0,
        ):
            score += 5

        if features.get(
            "privilege_escalation",
            0,
        ):
            score += 5

    elif prediction == "SUSPICIOUS":

        score = max(
            score,
            50,
        )

    else:

        score = min(
            score,
            30,
        )

    return min(
        score,
        100,
    )


def get_severity(
    risk_score: int,
) -> str:

    if risk_score >= 90:
        return "CRITICAL"

    if risk_score >= 70:
        return "HIGH"

    if risk_score >= 40:
        return "MEDIUM"

    return "LOW"


def analyze_and_create_incident(
    event: Dict[str, Any],
) -> Dict[str, Any]:

    analyzer = MLEventAnalyzer()

    prediction_result = analyzer.analyze(
        event
    )

    prediction = prediction_result[
        "prediction"
    ]

    confidence = prediction_result[
        "confidence"
    ]

    features = prediction_result[
        "features"
    ]

    risk_score = prediction_result[
        "risk_score"
    ]

    severity = prediction_result[
        "severity"
    ]

    incident = None

    if prediction in {
        "MALICIOUS",
        "SUSPICIOUS",
    }:

        incident = create_incident(
            title=(
                f"ML Detected "
                f"{prediction} Activity"
            ),

            description=(
                "SentinelX ML engine "
                "detected potentially "
                "malicious activity."
            ),

            severity=severity,

            source_ip=event.get(
                "source_ip"
            ),

            destination_ip=event.get(
                "destination_ip"
            ),

            ioc=event.get(
                "ioc"
            ),

            mitre_technique=event.get(
                "mitre_technique"
            ),

            evidence={
                "source":
                    "SentinelX ML Engine",

                "prediction":
                    prediction,

                "confidence":
                    confidence,

                "risk_score":
                    risk_score,

                "features":
                    features,
            },
        )

    return {
        **prediction_result,

        "incident_created":
            incident is not None,

        "incident":
            incident,
    }
