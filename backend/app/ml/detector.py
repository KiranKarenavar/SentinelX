from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    BASE_DIR
    / "app"
    / "ml"
    / "models"
    / "threat_model.joblib"
)


class MLThreatDetector:

    def __init__(self):

        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"ML model not found: {MODEL_PATH}"
            )

        self.model = joblib.load(MODEL_PATH)

    # =========================================================
    # Feature extraction
    # =========================================================

    def _extract_features(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        event_type = str(
            event.get(
                "event_type",
                "",
            )
        )

        process_name = str(
            event.get(
                "process_name",
                "",
            )
        ).lower()

        command_line = str(
            event.get(
                "command_line",
                event.get(
                    "command",
                    "",
                ),
            )
        )

        destination_ip = str(
            event.get(
                "destination_ip",
                "",
            )
        )

        suspicious = bool(
            event.get(
                "suspicious",
                False,
            )
        )

        # Encoded command detection
        encoded = int(
            event.get(
                "encoded",
                False,
            )
            or
            "-encodedcommand" in command_line.lower()
            or
            " -enc " in command_line.lower()
        )

        # Network connection detection
        network_connection = int(
            event.get(
                "network_connection",
                False,
            )
            or
            bool(destination_ip)
            or
            event_type == "network_connection"
        )

        # Failed login count
        failed_login = int(
            event.get(
                "failed_login",
                event.get(
                    "failed_logins",
                    0,
                ),
            )
            or 0
        )

        # Suspicious IP
        suspicious_ip = int(
            event.get(
                "suspicious_ip",
                False,
            )
            or suspicious
        )

        # Command length
        command_length = len(command_line)

        features = {
            "event_type": event_type,
            "process_name": process_name,
            "encoded": encoded,
            "network_connection": network_connection,
            "failed_login": failed_login,
            "suspicious_ip": suspicious_ip,
            "command_length": command_length,
        }

        return features

    # =========================================================
    # Severity calculation
    # =========================================================

    @staticmethod
    def _severity(
        risk_score: int,
    ) -> str:

        if risk_score >= 80:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 30:
            return "MEDIUM"

        return "LOW"

    # =========================================================
    # Prediction
    # =========================================================

    def predict(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not isinstance(
            event,
            dict,
        ):
            raise ValueError(
                "event must be a dictionary"
            )

        features = self._extract_features(
            event
        )

        # IMPORTANT:
        # sklearn Pipeline expects a 2D
        # dataframe, not a dictionary/list.
        dataframe = pd.DataFrame(
            [features]
        )

        prediction = int(
            self.model.predict(
                dataframe
            )[0]
        )

        probability = self.model.predict_proba(
            dataframe
        )[0]

        malicious_probability = float(
            probability[1]
            if len(probability) > 1
            else probability[0]
        )

        # Convert probability to 0-100
        risk_score = int(
            round(
                malicious_probability * 100
            )
        )

        severity = self._severity(
            risk_score
        )

        verdict = (
            "MALICIOUS"
            if prediction == 1
            else "BENIGN"
        )

        return {
            "verdict": verdict,
            "prediction": prediction,
            "risk_score": risk_score,
            "severity": severity,
            "malicious_probability": round(
                malicious_probability,
                4,
            ),
            "confidence": round(
                max(probability),
                4,
            ),
            "features": features,
            "model": "RandomForest",
            "model_path": str(
                MODEL_PATH
            ),
        }
