from typing import Any, Dict, List

from fastapi import (
    APIRouter,
    HTTPException,
)

from app.honeypot.models import (
    HoneypotEvent,
)

from app.honeypot.storage import (
    get_recent_honeypot_events,
)

from app.honeypot.engine import (
    HoneypotEngine,
)


router = APIRouter(
    prefix="/honeypot",
    tags=["Honeypot"],
)


engine = HoneypotEngine()


@router.post("/event")
async def receive_honeypot_event(
    event: HoneypotEvent,
) -> Dict[str, Any]:

    try:

        result = await engine.investigate(
            event.model_dump()
        )

        return result

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get("/events")
async def recent_honeypot_events(
    limit: int = 20,
) -> List[Dict[str, Any]]:

    if limit < 1:

        limit = 1

    if limit > 100:

        limit = 100

    try:

        return get_recent_honeypot_events(
            limit
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
