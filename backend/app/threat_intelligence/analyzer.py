from typing import Any, Dict

from app.threat_intelligence.enrichment import enrich_ip
from app.threat_intelligence.risk_engine import (
    calculate_risk_score,
)


def analyze_ip(
    intelligence,
) -> Dict[str, Any]:
    """
    Complete SentinelX IP analysis.

    Pipeline:

        Intelligence
             ↓
        Enrichment
             ↓
        Advanced Risk Scoring
             ↓
        Final Analysis
    """

    # -----------------------------------------
    # Step 1 — Enrichment
    # -----------------------------------------

    enrichment = enrich_ip(
        intelligence
    )

    # -----------------------------------------
    # Step 2 — Risk scoring
    # -----------------------------------------

    risk = calculate_risk_score(
        intelligence,
        enrichment,
    )

    # -----------------------------------------
    # Step 3 — Final result
    # -----------------------------------------

    return {
        "enrichment": enrichment,
        "risk": risk,
    }
