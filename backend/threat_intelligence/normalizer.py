from datetime import datetime
from typing import Any


def normalize_result(
    indicator: str,
    indicator_type: str,
    source: str,
    data: dict | None,
) -> dict:
    """
    Convert threat intelligence provider data
    into the common SentinelX IOC format.
    """

    result = {
        "indicator": indicator,
        "type": indicator_type.lower(),
        "source": source,
        "confidence": 0,
        "malware_family": None,
        "threat_actor": None,
        "first_seen": None,
        "last_seen": None,
    }

    if not data:
        return result

    if source == "OTX":
        result = normalize_otx(
            result,
            data,
        )

    elif source == "ThreatFox":
        result = normalize_threatfox(
            result,
            data,
        )

    elif source == "AbuseIPDB":
        result = normalize_abuseipdb(
            result,
            data,
        )

    elif source == "VirusTotal":
        result = normalize_virustotal(
            result,
            data,
        )

    return result


def normalize_otx(
    result: dict,
    data: dict,
) -> dict:
    """
    Normalize AlienVault OTX response.
    """

    pulse_info = data.get(
        "pulse_info",
        {},
    )

    pulse_count = pulse_info.get(
        "count",
        0,
    )

    result["confidence"] = min(
        100,
        pulse_count * 10,
    )

    return result


def normalize_threatfox(
    result: dict,
    data: dict,
) -> dict:
    """
    Normalize ThreatFox response.
    """

    entries = data.get(
        "data",
        [],
    )

    if not entries:
        return result

    entry = entries[0]

    result["confidence"] = int(
        entry.get(
            "confidence_level",
            0,
        )
    )

    result["malware_family"] = (
        entry.get("malware_printable")
        or entry.get("malware")
    )

    result["threat_actor"] = (
        entry.get("threat_actor")
    )

    result["first_seen"] = (
        entry.get("first_seen")
    )

    result["last_seen"] = (
        entry.get("last_seen")
    )

    return result


def normalize_abuseipdb(
    result: dict,
    data: dict,
) -> dict:
    """
    Normalize AbuseIPDB response.
    """

    abuse_data = data.get(
        "data",
        {},
    )

    result["confidence"] = int(
        abuse_data.get(
            "abuseConfidenceScore",
            0,
        )
    )

    result["first_seen"] = (
        abuse_data.get(
            "lastReportedAt"
        )
    )

    return result


def normalize_virustotal(
    result: dict,
    data: dict,
) -> dict:
    """
    Normalize VirusTotal response.
    """

    attributes = (
        data.get("data", {})
        .get("attributes", {})
    )

    analysis_stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    malicious = analysis_stats.get(
        "malicious",
        0,
    )

    suspicious = analysis_stats.get(
        "suspicious",
        0,
    )

    total = sum(
        analysis_stats.values()
    )

    if total > 0:
        result["confidence"] = int(
            (
                (malicious + suspicious)
                / total
            )
            * 100
        )

    result["first_seen"] = (
        attributes.get(
            "first_submission_date"
        )
    )

    result["last_seen"] = (
        attributes.get(
            "last_analysis_date"
        )
    )

    return result
