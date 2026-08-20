from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from hunt.service import ThreatHuntingService


router = APIRouter(
    prefix="/api/hunt",
    tags=["Threat Hunting"],
)


hunting_service = ThreatHuntingService()


class HuntRequest(BaseModel):
    query: str = Field(
        ...,
        min_length=1,
        description="IOC, IP, domain, hash, or other hunting value",
    )


@router.post("")
async def hunt(
    request: HuntRequest,
) -> dict[str, Any]:
    """
    Search an IOC across SentinelX security sources.
    """

    try:

        result = await hunting_service.hunt(
            request.query
        )

        return result

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Threat hunting failed: {exc}",
        )
