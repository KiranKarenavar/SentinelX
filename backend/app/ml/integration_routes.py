from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from app.ml.integration import (
    analyze_and_create_incident,
)


router = APIRouter(
    prefix="/ml",
    tags=["Machine Learning"],
)


@router.post("/analyze")
async def analyze_event(
    event: Dict[str, Any],
):

    try:

        return analyze_and_create_incident(
            event
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
