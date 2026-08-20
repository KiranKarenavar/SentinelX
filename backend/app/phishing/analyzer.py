from typing import Any, Dict


def analyze_email(
    parsed_email: Dict[str, Any],
    iocs: Dict[str, Any],
) -> Dict[str, Any]:

    score = 0
    reasons = []

    headers = parsed_email.get(
        "headers",
        {}
    )

    body = parsed_email.get(
        "body",
        ""
    )

    sender = headers.get(
        "from"
    )

    reply_to = headers.get(
        "reply_to"
    )

    subject = headers.get(
        "subject"
    )

    urls = iocs.get(
        "urls",
        []
    )

    domains = iocs.get(
        "domains",
        []
    )

    ips = iocs.get(
        "ips",
        []
    )

    # Reply-To mismatch
    if sender and reply_to:

        sender_domain = (
            sender.split("@")[-1]
            .replace(">", "")
            .strip()
        )

        reply_domain = (
            reply_to.split("@")[-1]
            .replace(">", "")
            .strip()
        )

        if sender_domain.lower() != reply_domain.lower():

            score += 25

            reasons.append(
                "Sender and Reply-To domains differ"
            )

    # URLs
    if urls:

        score += min(
            len(urls) * 10,
            30
        )

        reasons.append(
            f"{len(urls)} URL(s) found"
        )

    # Direct IP URLs / IP indicators
    if ips:

        score += min(
            len(ips) * 20,
            30
        )

        reasons.append(
            f"{len(ips)} IP address(es) found"
        )

    # Suspicious keywords
    suspicious_keywords = [
        "verify",
        "suspended",
        "urgent",
        "password",
        "login",
        "account",
        "payment",
        "security alert",
    ]

    text = (
        f"{subject or ''} "
        f"{body or ''}"
    ).lower()

    matched = [
        keyword
        for keyword in suspicious_keywords
        if keyword in text
    ]

    if matched:

        score += min(
            len(matched) * 5,
            25
        )

        reasons.append(
            "Suspicious keywords: "
            + ", ".join(matched)
        )

    score = min(
        score,
        100
    )

    if score >= 75:

        verdict = "PHISHING"

    elif score >= 45:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LIKELY_BENIGN"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }

