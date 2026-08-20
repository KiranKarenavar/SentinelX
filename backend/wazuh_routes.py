from fastapi import APIRouter, HTTPException

from wazuh.client import WazuhClient
from wazuh.service import process_wazuh_alert


router = APIRouter(
    prefix="/api/wazuh",
    tags=["Wazuh"],
)


wazuh_client = WazuhClient()


@router.get("/agents")
async def get_wazuh_agents(
    limit: int = 10,
):
    """
    Retrieve Wazuh agents.
    """

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100",
        )

    try:
        return await wazuh_client.get_agents(
            limit=limit
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get("/manager")
async def get_wazuh_manager():
    """
    Retrieve Wazuh manager information.
    """

    try:
        return await wazuh_client.get_manager_info()

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post("/process-alert")
async def process_alert(
    alert: dict,
):
    """
    Process a Wazuh alert and send
    extracted IOCs to the intelligence engine.
    """

    try:
        results = await process_wazuh_alert(
            alert
        )

        return {
            "status": "processed",
            "ioc_count": len(results),
            "results": results,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
