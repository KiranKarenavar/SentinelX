from typing import Any, Dict


def normalize_ioc(
    ioc_type: str,
    value: str,
    source: str,
    raw_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create the common SentinelX IOC structure.
    """

    return {
        "ioc_type": ioc_type,
        "value": value,
        "source": source,
        "confidence": None,
        "malicious": None,
        "country": None,
        "isp": None,
        "first_seen": None,
        "last_seen": None,
        "tags": [],
        "raw_data": raw_data,
    }


def normalize_otx_ip(
    ip_address: str,
    raw_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Normalize an AlienVault OTX IPv4 response.
    """

    return normalize_ioc(
        ioc_type="ipv4",
        value=ip_address,
        source="otx",
        raw_data=raw_data,
    )

def normalize_abuseipdb_ip(
    ip_address: str,
    raw_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Normalize an AbuseIPDB IPv4 response.
    """

    data = raw_data.get("data", {})

    abuse_score = data.get("abuseConfidenceScore")

    return normalize_ioc(
        ioc_type="ipv4",
        value=ip_address,
        source="abuseipdb",
        raw_data=raw_data,
    ) | {
        "confidence": abuse_score,
        "malicious": (
            abuse_score > 0
            if abuse_score is not None
            else None
        ),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "last_seen": data.get("lastReportedAt"),
        "tags": [],
    }


def normalize_threatfox_ioc(
    ioc_value: str,
    raw_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Normalize a ThreatFox IOC response safely.
    """

    query_status = raw_data.get("query_status")
    data = raw_data.get("data")

    # ThreatFox did not find this IOC.
    if query_status == "no_result":
        return normalize_ioc(
            ioc_type="ipv4",
            value=ioc_value,
            source="threatfox",
            raw_data=raw_data,
        ) | {
            "malicious": False,
        }

    first_match = {}

    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            first_match = data[0]

    elif isinstance(data, dict):
        first_match = data

    return normalize_ioc(
        ioc_type=first_match.get("ioc_type", "unknown"),
        value=ioc_value,
        source="threatfox",
        raw_data=raw_data,
    ) | {
        "confidence": first_match.get("confidence_level"),
        "malicious": True if first_match else None,
        "first_seen": first_match.get("first_seen"),
        "last_seen": first_match.get("last_seen"),
        "tags": first_match.get("tags", []),
    }
