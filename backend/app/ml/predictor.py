from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "sentinelx_threat_model.joblib"
)


class ThreatPredictor:

    def __init__(self):

        if not MODEL_PATH.exists():

            raise FileNotFoundError(
                f"ML model not found: {MODEL_PATH}"
            )

        package = joblib.load(
            MODEL_PATH
        )

        self.model = package["model"]

        self.features = package[
            "features"
        ]

    def predict(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:

        row = {}

        for feature in self.features:

            value = features.get(
                feature,
                0,
            )

            try:

                value = int(value)

            except (
                TypeError,
                ValueError,
            ):

                value = 0

            row[feature] = value

        dataframe = pd.DataFrame(
            [row],
            columns=self.features,
        )

        prediction = self.model.predict(
            dataframe
        )[0]

        probabilities = (
            self.model.predict_proba(
                dataframe
            )[0]
        )

        classes = list(
            self.model.classes_
        )

        confidence = max(
            probabilities
        )

        return {
            "prediction": str(
                prediction
            ),
            "confidence": round(
                float(confidence),
                4,
            ),
            "probabilities": {
                str(label): round(
                    float(probability),
                    4,
                )
                for label, probability
                in zip(
                    classes,
                    probabilities,
                )
            },
            "features": row,
        }
