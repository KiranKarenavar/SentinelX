import asyncio

from .otx import lookup_otx
from .threatfox import lookup_threatfox
from .abuseipdb import lookup_abuseipdb
from .virustotal import lookup_virustotal

from .normalizer import normalize_result
from .scorer import calculate_risk


async def aggregate_intelligence(
    indicator: str,
    indicator_type: str,
):
    """
    Query multiple threat intelligence providers,
    normalize their responses, deduplicate sources,
    and calculate a SentinelX risk score.
    """

    indicator_type = indicator_type.upper()

    # -----------------------------------
    # Query intelligence providers
    # -----------------------------------

    tasks = [
        lookup_otx(
            indicator,
            indicator_type,
        ),

        lookup_threatfox(
            indicator,
        ),

        lookup_abuseipdb(
            indicator,
        ),

        lookup_virustotal(
            indicator,
            indicator_type,
        ),
    ]

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    # -----------------------------------
    # Normalize responses
    # -----------------------------------

    normalized_results = []

    for result in results:

        if isinstance(
            result,
            Exception,
        ):
            continue

        if result.get("status") != "success":
            continue

        normalized = normalize_result(
            indicator=indicator,
            indicator_type=indicator_type,
            source=result["source"],
            data=result.get("data"),
        )

        normalized_results.append(
            normalized
        )

    # -----------------------------------
    # Deduplicate sources
    # -----------------------------------

    unique_sources = {}

    for result in normalized_results:

        source = result["source"]

        if source not in unique_sources:

            unique_sources[source] = result

    normalized_results = list(
        unique_sources.values()
    )

    # -----------------------------------
    # Get detected sources
    # -----------------------------------

    detected_sources = [
        result["source"]
        for result in normalized_results
    ]

    # -----------------------------------
    # Calculate risk
    # -----------------------------------

    risk = calculate_risk(
        detected_sources=detected_sources
    )

    # -----------------------------------
    # Final SentinelX result
    # -----------------------------------

    return {
        "indicator": indicator,

        "indicator_type": (
            indicator_type.lower()
        ),

        "sources": normalized_results,

        "source_count": len(
            detected_sources
        ),

        "detected_sources": (
            detected_sources
        ),

        "risk_score": (
            risk["risk_score"]
        ),

        "severity": (
            risk["severity"]
        ),
    }
