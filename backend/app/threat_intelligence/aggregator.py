import asyncio
from typing import Any, Dict

from app.threat_intelligence.otx import get_ip_reputation
from app.threat_intelligence.abuseipdb import check_ip_reputation
from app.threat_intelligence.threatfox import query_threatfox

from app.threat_intelligence.normalizer import (
    normalize_otx_ip,
    normalize_abuseipdb_ip,
    normalize_threatfox_ioc,
)

from app.threat_intelligence.deduplicator import (
    deduplicate_iocs,
)


async def fetch_otx(ip_address: str) -> Dict[str, Any]:
    """Fetch and normalize OTX intelligence."""

    try:
        data = await get_ip_reputation(ip_address)

        return normalize_otx_ip(
            ip_address=ip_address,
            raw_data=data,
        )

    except Exception as error:
        return {
            "source": "otx",
            "error": str(error),
        }


async def fetch_abuseipdb(ip_address: str) -> Dict[str, Any]:
    """Fetch and normalize AbuseIPDB intelligence."""

    try:
        data = await check_ip_reputation(ip_address)

        return normalize_abuseipdb_ip(
            ip_address=ip_address,
            raw_data=data,
        )

    except Exception as error:
        return {
            "source": "abuseipdb",
            "error": str(error),
        }


async def fetch_threatfox(ip_address: str) -> Dict[str, Any]:
    """Fetch and normalize ThreatFox intelligence."""

    try:
        data = await query_threatfox(ip_address)

        return normalize_threatfox_ioc(
            ioc_value=ip_address,
            raw_data=data,
        )

    except Exception as error:
        return {
            "source": "threatfox",
            "error": str(error),
        }


async def aggregate_ip_intelligence(
    ip_address: str,
) -> Dict[str, Any]:
    """Query all threat-intelligence providers concurrently."""

    results = await asyncio.gather(
        fetch_otx(ip_address),
        fetch_abuseipdb(ip_address),
        fetch_threatfox(ip_address),
    )

    sources = []

    for result in results:
        if "error" not in result:
            sources.append(result["source"])

    deduplicated = deduplicate_iocs(results)

    return {
        "ioc": ip_address,
        "sources": sources,
        "results": results,
        "deduplicated": deduplicated,
    }
