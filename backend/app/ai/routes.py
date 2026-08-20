from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from app.ai.agent import SentinelXSOCAgent
from app.ai.llm import LLMService


router = APIRouter(
    prefix="/ai",
    tags=["AI SOC Agent"],
)


agent = SentinelXSOCAgent()

llm = LLMService()


@router.get("/health")
async def ai_health():

    return {
        "status": "success",
        "agent": agent.name,
        "version": agent.version,
        "llm_provider": llm.provider,
        "status_detail": "ready",
    }


@router.post("/analyze")
async def analyze_event(
    payload: Dict[str, Any]
):

    try:

        event = payload.get(
            "event",
            {}
        )

        detection = payload.get(
            "detection",
            {}
        )

        threat_intelligence = payload.get(
            "threat_intelligence",
            []
        )

        if not isinstance(
            event,
            dict
        ):

            raise HTTPException(
                status_code=400,
                detail="event must be an object"
            )

        if not isinstance(
            detection,
            dict
        ):

            raise HTTPException(
                status_code=400,
                detail="detection must be an object"
            )

        if not isinstance(
            threat_intelligence,
            list
        ):

            threat_intelligence = []

        local_analysis = agent.analyze(
            event=event,
            detection=detection,
            threat_intelligence=(
                threat_intelligence
            ),
        )

        llm_result = await llm.analyze(
            {
                "event": event,
                "detection": detection,
                "threat_intelligence":
                    threat_intelligence,
            }
        )

        return {
            "status": "success",

            "local_analysis":
                local_analysis,

            "llm_analysis":
                llm_result,
        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
