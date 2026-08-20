from typing import Any, Dict, List


def _safe_int(
    value: Any,
    default: int = 0,
) -> int:
    """
    Safely convert a value to an integer.
    """

    if value is None:
        return default

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, (int, float)):
        return int(value)

    if isinstance(value, list):
        return default

    if isinstance(value, dict):
        return default

    try:
        return int(float(value))

    except (
        TypeError,
        ValueError,
    ):
        return default


def _normalize_malicious(
    value: Any,
) -> Any:
    """
    Normalize malicious values.
    """

    if isinstance(value, bool):
        return value

    if value is None:
        return None

    if isinstance(value, str):

        value = value.strip().lower()

        if value == "true":
            return True

        if value == "false":
            return False

    return value


def _calculate_provider_score(
    confidence: Any,
    malicious: Any,
) -> int:
    """
    Calculate the risk contribution
    from one intelligence provider.

    Maximum = 50 points.
    """

    malicious = _normalize_malicious(
        malicious
    )

    confidence = _safe_int(
        confidence,
        0,
    )

    if malicious is not True:
        return 0

    if confidence >= 70:
        return 50

    if confidence >= 50:
        return 40

    if confidence >= 25:
        return 30

    if confidence > 0:
        return 20

    return 25


def calculate_risk_score(
    intelligence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Calculate SentinelX IOC risk score.

    Returns both:

        score
        risk_score

    so existing SentinelX components remain
    compatible.
    """

    if not isinstance(
        intelligence,
        list,
    ):

        intelligence = []

    total_score = 0

    reasons = []

    provider_scores = []

    malicious_sources = 0

    # =========================================
    # Provider analysis
    # =========================================

    for item in intelligence:

        if not isinstance(
            item,
            dict,
        ):

            continue

        source = str(
            item.get(
                "source",
                "unknown",
            )
        )

        confidence = item.get(
            "confidence",
            0,
        )

        malicious = _normalize_malicious(
            item.get(
                "malicious",
                None,
            )
        )

        provider_score = (
            _calculate_provider_score(
                confidence,
                malicious,
            )
        )

        total_score += provider_score

        if malicious is True:

            malicious_sources += 1

            reasons.append(
                f"{source} reported the IOC as malicious"
            )

        provider_scores.append(
            {
                "source": source,
                "score": provider_score,
                "confidence": _safe_int(
                    confidence,
                    0,
                ),
                "malicious": malicious,
            }
        )

    # =========================================
    # Multiple malicious sources
    # =========================================

    if malicious_sources >= 2:

        total_score += 25

        reasons.append(
            "Multiple threat-intelligence sources "
            "reported the IOC as malicious"
        )

    # =========================================
    # Additional intelligence indicators
    # =========================================

    for item in intelligence:

        if not isinstance(
            item,
            dict,
        ):

            continue

        source = str(
            item.get(
                "source",
                "",
            )
        ).lower()

        raw_data = item.get(
            "raw_data",
            {},
        )

        if not isinstance(
            raw_data,
            dict,
        ):

            continue

        # -----------------------------------------
        # AbuseIPDB
        # -----------------------------------------

        if source == "abuseipdb":

            data = raw_data.get(
                "data",
                {},
            )

            if isinstance(
                data,
                dict,
            ):

                abuse_confidence = _safe_int(
                    data.get(
                        "abuseConfidenceScore",
                        0,
                    ),
                    0,
                )

                if abuse_confidence >= 50:

                    reasons.append(
                        "AbuseIPDB reports a high "
                        "abuse confidence score"
                    )

        # -----------------------------------------
        # OTX
        # -----------------------------------------

        elif source == "otx":

            pulse_info = raw_data.get(
                "pulse_info",
                {},
            )

            if isinstance(
                pulse_info,
                dict,
            ):

                pulse_count = _safe_int(
                    pulse_info.get(
                        "count",
                        0,
                    ),
                    0,
                )

                if pulse_count > 0:

                    reasons.append(
                        "AlienVault OTX contains "
                        "threat pulses for the IOC"
                    )

        # -----------------------------------------
        # ThreatFox
        # -----------------------------------------

        elif source == "threatfox":

            query_status = raw_data.get(
                "query_status"
            )

            if query_status == "no_result":
                continue

            data = raw_data.get(
                "data"
            )

            if isinstance(
                data,
                list,
            ) and data:

                reasons.append(
                    "ThreatFox contains threat "
                    "intelligence for the IOC"
                )

    # =========================================
    # Limit score
    # =========================================

    if total_score > 100:
        total_score = 100

    if total_score < 0:
        total_score = 0

    # =========================================
    # Severity
    # =========================================

    if total_score >= 80:

        severity = "CRITICAL"

    elif total_score >= 60:

        severity = "HIGH"

    elif total_score >= 30:

        severity = "MEDIUM"

    elif total_score >= 10:

        severity = "LOW"

    else:

        severity = "INFO"

    # =========================================
    # Verdict
    # =========================================

    if total_score >= 60:

        verdict = "MALICIOUS"

    elif total_score >= 30:

        verdict = "SUSPICIOUS"

    else:

        verdict = "BENIGN"

    # =========================================
    # Default reason
    # =========================================

    if not reasons:

        reasons.append(
            "No malicious evidence was reported "
            "by the available threat-intelligence "
            "sources"
        )

    # =========================================
    # Final result
    # =========================================

    return {
        # Current name
        "risk_score": total_score,

        # Backward-compatible name
        "score": total_score,

        "severity": severity,

        "verdict": verdict,

        "reasons": reasons,

        "provider_scores": provider_scores,
    }


def calculate_verdict(
    intelligence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Backward-compatible wrapper.
    """

    return calculate_risk_score(
        intelligence
    )
