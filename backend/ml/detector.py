import joblib
import numpy as np


MODEL_PATH = "ml/isolation_forest.joblib"


class AnomalyDetector:

    def __init__(self):
        self.model = joblib.load(MODEL_PATH)

    def predict(self, features):
        """
        Return anomaly prediction and score.
        """

        values = np.array([[
            features["failed_logins"],
            features["connection_count"],
            features["unique_ips"],
            features["unique_destinations"],
            features["bytes_sent"],
            features["bytes_received"],
            features["process_count"],
        ]])

        prediction = self.model.predict(values)[0]

        decision_score = self.model.decision_function(values)[0]

        # Isolation Forest:
        # -1 = anomaly
        #  1 = normal

        if prediction == -1:
            verdict = "ANOMALY"
        else:
            verdict = "NORMAL"

        return {
            "verdict": verdict,
            "decision_score": float(decision_score),
        }
