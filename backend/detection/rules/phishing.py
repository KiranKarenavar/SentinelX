from typing import Any


PHISHING_KEYWORDS = {
    "urgent",
    "verify your account",
    "account suspended",
    "click here",
    "confirm your password",
    "reset your password",
    "payment required",
    "security alert",
}


def detect_phishing(
    email: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect basic phishing indicators in email content.
    """

    subject = str(
        email.get("subject", "")
    ).lower()

    body = str(
        email.get("body", "")
    ).lower()

    content = f"{subject} {body}"

    matches = [
        keyword
        for keyword in PHISHING_KEYWORDS
        if keyword in content
    ]

    if not matches:
        return []

    return [
        {
            "detection_type": "PHISHING",
            "matched_keywords": matches,
            "severity": "HIGH",
            "description": (
                "Potential phishing email detected"
            ),
        }
    ]
