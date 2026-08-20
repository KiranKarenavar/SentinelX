from fastapi import APIRouter, HTTPException

from threat_intelligence.aggregator import (
    aggregate_intelligence,
)


router = APIRouter(
    prefix="/api/intelligence",
    tags=["Threat Intelligence"],
)


@router.get("/lookup")
async def intelligence_lookup(
    indicator: str,
    indicator_type: str = "IP",
):
    """
    Aggregate threat intelligence
    from multiple providers.
    """

    if not indicator.strip():
        raise HTTPException(
            status_code=400,
            detail="Indicator cannot be empty",
        )

    result = await aggregate_intelligence(
        indicator=indicator.strip(),
        indicator_type=indicator_type,
    )

    return result
