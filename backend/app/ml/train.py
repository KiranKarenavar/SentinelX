from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET = BASE_DIR / "tests" / "ml" / "training_data.csv"

MODEL_DIR = BASE_DIR / "app" / "ml" / "models"

MODEL_PATH = MODEL_DIR / "threat_model.joblib"


def train_model():

    print("=" * 60)
    print("SENTINELX ML THREAT DETECTION TRAINING")
    print("=" * 60)

    df = pd.read_csv(DATASET)

    print(f"\nDataset records: {len(df)}")

    X = df.drop(columns=["label"])
    y = df["label"]

    categorical_features = [
        "event_type",
        "process_name",
    ]

    numerical_features = [
        "encoded",
        "network_connection",
        "failed_login",
        "suspicious_ip",
        "command_length",
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_features,
            ),
            (
                "numerical",
                "passthrough",
                numerical_features,
            ),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight="balanced",
    )

    pipeline = __import__("sklearn.pipeline", fromlist=["Pipeline"]).Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", model),
        ]
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    print(f"\nAccuracy: {accuracy:.2f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        pipeline,
        MODEL_PATH,
    )

    print("\nModel saved:")
    print(MODEL_PATH)

    print("\nTRAINING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    train_model()
