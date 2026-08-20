from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_DIR = BASE_DIR / "models"

MODEL_DIR.mkdir(
    exist_ok=True
)

MODEL_PATH = (
    MODEL_DIR / "sentinelx_threat_model.joblib"
)


def build_dataset():

    data = [
        # connection_count,
        # failed_logins,
        # suspicious_port,
        # known_bad_ip,
        # encoded_command,
        # privilege_escalation,
        # label

        [1, 0, 0, 0, 0, 0, "BENIGN"],
        [2, 0, 0, 0, 0, 0, "BENIGN"],
        [3, 0, 0, 0, 0, 0, "BENIGN"],
        [1, 1, 0, 0, 0, 0, "BENIGN"],

        [10, 5, 1, 0, 0, 0, "SUSPICIOUS"],
        [15, 8, 1, 0, 0, 0, "SUSPICIOUS"],
        [20, 10, 1, 0, 0, 0, "SUSPICIOUS"],
        [8, 6, 1, 0, 0, 1, "SUSPICIOUS"],

        [30, 15, 1, 1, 1, 1, "MALICIOUS"],
        [40, 20, 1, 1, 1, 1, "MALICIOUS"],
        [50, 25, 1, 1, 1, 1, "MALICIOUS"],
        [35, 18, 1, 1, 0, 1, "MALICIOUS"],
        [45, 22, 1, 1, 1, 0, "MALICIOUS"],
    ]

    columns = [
        "connection_count",
        "failed_logins",
        "suspicious_port",
        "known_bad_ip",
        "encoded_command",
        "privilege_escalation",
        "label",
    ]

    return pd.DataFrame(
        data,
        columns=columns,
    )


def train():

    df = build_dataset()

    X = df.drop(
        columns=["label"]
    )

    y = df["label"]

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y,
        )
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(
        X_train,
        y_train,
    )

    predictions = model.predict(
        X_test
    )

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    joblib.dump(
        {
            "model": model,
            "features": list(X.columns),
        },
        MODEL_PATH,
    )

    print(
        f"Model saved to: {MODEL_PATH}"
    )


if __name__ == "__main__":
    train()
