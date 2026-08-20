def calculate_severity(score: int) -> str:
    """
    Convert a numeric risk score into a severity level.
    """

    score = max(0, min(score, 100))

    if score <= 20:
        return "INFORMATIONAL"

    if score <= 40:
        return "LOW"

    if score <= 60:
        return "MEDIUM"

    if score <= 80:
        return "HIGH"

    return "CRITICAL"


def severity_from_wazuh_level(level: int) -> str:
    """
    Convert Wazuh rule level into SentinelX severity.
    """

    if level <= 3:
        return "LOW"

    if level <= 6:
        return "MEDIUM"

    if level <= 11:
        return "HIGH"

    return "CRITICAL"
