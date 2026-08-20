SOURCE_SCORES = {
    "OTX": 20,
    "ThreatFox": 25,
    "AbuseIPDB": 20,
    "VirusTotal": 25,
}


def calculate_risk(
    detected_sources: list[str],
) -> dict:
    """
    Calculate SentinelX IOC risk score.

    Source weights:

    OTX        = 20
    ThreatFox  = 25
    AbuseIPDB  = 20
    VirusTotal = 25

    Multiple sightings = +10

    Maximum score = 100
    """

    score = 0

    normalized_sources = {
        source.lower()
        for source in detected_sources
    }

    # -----------------------------------
    # Add source-specific scores
    # -----------------------------------

    for source, points in SOURCE_SCORES.items():

        if source.lower() in normalized_sources:
            score += points

    # -----------------------------------
    # Multiple source sightings
    # -----------------------------------

    if len(normalized_sources) >= 2:
        score += 10

    # -----------------------------------
    # Maximum score
    # -----------------------------------

    score = min(
        score,
        100,
    )

    # -----------------------------------
    # Determine severity
    # -----------------------------------

    if score <= 20:
        severity = "INFORMATIONAL"

    elif score <= 40:
        severity = "LOW"

    elif score <= 60:
        severity = "MEDIUM"

    elif score <= 80:
        severity = "HIGH"

    else:
        severity = "CRITICAL"

    return {
        "risk_score": score,
        "severity": severity,
        "detected_sources": list(
            normalized_sources
        ),
    }
