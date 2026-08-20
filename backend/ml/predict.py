from ml.detector import AnomalyDetector


detector = AnomalyDetector()


def analyze_event(event):
    result = detector.predict(event)

    return {
        "ml_verdict": result["verdict"],
        "anomaly_score": result["decision_score"],
        "features": event,
    }
