import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


MODEL_PATH = "ml/isolation_forest.joblib"


def generate_training_data(samples=500):
    """
    Generate baseline/mostly-normal behavioral data.
    """

    rng = np.random.default_rng(42)

    data = np.column_stack([
        rng.poisson(2, samples),      # failed_logins
        rng.poisson(10, samples),     # connection_count
        rng.poisson(3, samples),      # unique_ips
        rng.poisson(2, samples),      # unique_destinations
        rng.poisson(5000, samples),   # bytes_sent
        rng.poisson(10000, samples),  # bytes_received
        rng.poisson(5, samples),      # process_count
    ])

    return data


def train_model():
    X = generate_training_data()

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )

    model.fit(X)

    os.makedirs("ml", exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    print(f"Model saved to: {MODEL_PATH}")


if __name__ == "__main__":
    train_model()
