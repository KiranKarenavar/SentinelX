from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from app.threat_intelligence.aggregator import (
    aggregate_ip_intelligence,
)

from app.threat_intelligence.ioc_detector import (
    detect_ioc_type,
)

from app.threat_intelligence.enrichment_router import (
    enrich_ioc,
)

from app.threat_intelligence.risk_engine import (
    calculate_verdict,
)

from app.threat_intelligence.storage import (
    store_enrichment_result,
)


router = APIRouter(
    prefix="/api/threat-intelligence",
    tags=["Threat Intelligence"],
)


@router.get("/check/{ioc}")
async def check_ioc(
    ioc: str,
) -> Dict[str, Any]:
    """
    Query threat intelligence sources for an IOC.
    """

    try:

        ioc_type = detect_ioc_type(ioc)

        if ioc_type == "ipv4":

            result = await aggregate_ip_intelligence(
                ioc
            )

        else:

            raise HTTPException(
                status_code=400,
                detail=(
                    f"IOC type '{ioc_type}' "
                    "is not yet supported by "
                    "the threat-intelligence aggregator."
                ),
            )

        return {
            "status": "success",
            "ioc": ioc,
            "ioc_type": ioc_type,
            **result,
        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get("/analyze/{ioc}")
async def analyze_ioc(
    ioc: str,
) -> Dict[str, Any]:
    """
    Complete SentinelX IOC analysis.

    Workflow:

        IOC
        ↓
        IOC Detection
        ↓
        Threat Intelligence
        ↓
        Enrichment
        ↓
        Risk Analysis
        ↓
        PostgreSQL
        ↓
        API Response
    """

    try:

        # =========================================
        # STEP 1 — Detect IOC type
        # =========================================

        ioc_type = detect_ioc_type(ioc)

        if ioc_type == "unknown":

            raise HTTPException(
                status_code=400,
                detail="Unsupported or invalid IOC.",
            )

        # =========================================
        # STEP 2 — Query threat intelligence
        # =========================================

        if ioc_type == "ipv4":

            intelligence_result = (
                await aggregate_ip_intelligence(
                    ioc
                )
            )

        else:

            raise HTTPException(
                status_code=400,
                detail=(
                    f"IOC type '{ioc_type}' "
                    "is detected but its "
                    "external threat-intelligence "
                    "query is not implemented yet."
                ),
            )

        # =========================================
        # STEP 3 — Extract intelligence
        # =========================================

        intelligence = intelligence_result.get(
            "results",
            []
        )

        if not isinstance(
            intelligence,
            list,
        ):

            intelligence = []

        # =========================================
        # STEP 4 — Enrichment
        # =========================================

        enrichment_result = enrich_ioc(
            ioc,
            intelligence,
        )

        if not isinstance(
            enrichment_result,
            dict,
        ):

            enrichment_result = {}

        enrichment = enrichment_result.get(
            "enrichment",
            enrichment_result,
        )

        if not isinstance(
            enrichment,
            dict,
        ):

            enrichment = {}

        # =========================================
        # STEP 5 — Risk analysis
        # =========================================

        risk_result = calculate_verdict(
            intelligence
        )

        if not isinstance(
            risk_result,
            dict,
        ):

            risk_result = {}

        risk_score = risk_result.get(
            "risk_score",
            risk_result.get(
                "score",
                0,
            ),
        )

        severity = risk_result.get(
            "severity",
            "LOW",
        )

        verdict = risk_result.get(
            "verdict",
            "UNKNOWN",
        )

        reasons = risk_result.get(
            "reasons",
            [],
        )

        provider_scores = risk_result.get(
            "provider_scores",
            [],
        )

        # =========================================
        # STEP 6 — Store analysis
        # =========================================

        stored = store_enrichment_result(
            indicator=ioc,
            indicator_type=ioc_type,
            risk_score=int(risk_score),
            severity=severity,
            verdict=verdict,
            enrichment=enrichment,
        )

        # =========================================
        # STEP 7 — Return result
        # =========================================

        return {
            "status": "success",
            "ioc": ioc,
            "ioc_type": ioc_type,

            "risk": {
                "score": int(risk_score),
                "severity": severity,
                "verdict": verdict,
                "reasons": reasons,
                "provider_scores": provider_scores,
            },

            "enrichment": enrichment,

            "threat_intelligence": intelligence,

            "storage": stored,
        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
