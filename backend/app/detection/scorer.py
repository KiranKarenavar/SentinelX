SEVERITY_SCORE = {
    "INFO": 10,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100
}


def calculate_score(
    severity: str,
    ioc_score: int = 0,
    correlation_bonus: int = 0
) -> int:

    base_score = SEVERITY_SCORE.get(
        severity.upper(),
        0
    )

    score = (
        base_score
        + ioc_score
        + correlation_bonus
    )

    return min(score, 100)


def calculate_severity(score: int) -> str:

    if score >= 90:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "INFO"
