from typing import Any, Dict, Optional

from app.ml.predictor import ThreatPredictor
from app.incidents.storage import create_incident


class MLIncidentService:

    def __init__(self):
        self.predictor = ThreatPredictor()

    def calculate_risk_score(
        self,
        prediction: Dict[str, Any],
    ) -> int:

        label = str(
            prediction.get("prediction", "")
        ).upper()

        confidence = float(
            prediction.get("confidence", 0)
        )

        if label == "MALICIOUS":
            score = 70 + int(confidence * 30)

        elif label == "SUSPICIOUS":
            score = 40 + int(confidence * 30)

        else:
            score = int(confidence * 20)

        return max(0, min(score, 100))

    def calculate_severity(
        self,
        risk_score: int,
    ) -> str:

        if risk_score >= 80:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 30:
            return "MEDIUM"

        return "INFO"

    def analyze(
        self,
        event: Dict[str, Any],
        create_incident_if_malicious: bool = True,
    ) -> Dict[str, Any]:

        prediction = self.predictor.predict(event)

        risk_score = self.calculate_risk_score(
            prediction
        )

        severity = self.calculate_severity(
            risk_score
        )

        label = str(
            prediction["prediction"]
        ).upper()

        incident = None

        if (
            create_incident_if_malicious
            and label == "MALICIOUS"
            and risk_score >= 80
        ):

            source_ip = event.get(
                "source_ip"
            )

            destination_ip = event.get(
                "destination_ip"
            )

            ioc = event.get(
                "ioc"
            )

            mitre_technique = event.get(
                "mitre_technique"
            )

            incident = create_incident(

                title=(
                    "ML Detected Malicious Activity"
                ),

                description=(
                    "SentinelX ML engine detected "
                    "malicious activity."
                ),

                severity=severity,

                source_ip=source_ip,

                destination_ip=destination_ip,

                ioc=ioc,

                mitre_technique=mitre_technique,

                evidence={
                    "source": event.get(
                        "source",
                        "ML Detection Engine",
                    ),

                    "ml_prediction": label,

                    "ml_confidence": prediction[
                        "confidence"
                    ],

                    "risk_score": risk_score,

                    "ml_probabilities": prediction[
                        "probabilities"
                    ],

                    "features": prediction[
                        "features"
                    ],
                },
            )

        return {
            "prediction": prediction,

            "risk_score": risk_score,

            "severity": severity,

            "incident_created": (
                incident is not None
            ),

            "incident": incident,
        }
