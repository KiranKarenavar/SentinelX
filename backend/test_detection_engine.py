from app.detection.engine import DetectionEngine
from app.detection.correlator import CorrelationEngine
from app.detection.scorer import calculate_score, calculate_severity


def main():

    print("=" * 60)
    print("SENTINELX PHASE 5 DETECTION ENGINE TEST")
    print("=" * 60)

    event1 = {
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand ABC123"
    }

    event2 = {
        "event_type": "network_connection",
        "destination_ip": "8.8.8.8",
        "suspicious": True
    }

    engine = DetectionEngine()

    print("\n[1] Detection Rules")

    detections = engine.evaluate(event1)

    for detection in detections:
        print(detection)

    print("\n[2] Correlation")

    correlator = CorrelationEngine()

    correlator.add_event(event1)
    correlator.add_event(event2)

    correlations = correlator.correlate()

    for correlation in correlations:
        print(correlation)

    print("\n[3] Risk Scoring")

    score = calculate_score(
        severity="HIGH",
        ioc_score=20,
        correlation_bonus=10
    )

    severity = calculate_severity(score)

    print({
        "score": score,
        "severity": severity
    })

    print("\n" + "=" * 60)
    print("PHASE 5 ENGINE TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
