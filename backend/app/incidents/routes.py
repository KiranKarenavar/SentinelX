from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.incidents.models import (
    IncidentCreate,
    IncidentStatusUpdate,
)

from app.incidents.storage import (
    create_incident,
    get_incident_by_identifier,
    list_incidents,
    update_incident_status,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Incident Response"],
)


@router.post("")
async def create(
    request: IncidentCreate,
):

    try:

        incident = create_incident(
            title=request.title,
            description=request.description,
            severity=request.severity,
            source_ip=request.source_ip,
            destination_ip=request.destination_ip,
            ioc=request.ioc,
            mitre_technique=(
                request.mitre_technique
            ),
            evidence=request.evidence,
        )

        return {
            "status": "success",
            "incident": incident,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get("")
async def get_incidents(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
):

    try:

        incidents = list_incidents(
            limit
        )

        return {
            "status": "success",
            "count": len(
                incidents
            ),
            "incidents": incidents,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get("/{incident_id}")
async def get_one(
    incident_id: str,
):

    try:

        incident = (
            get_incident_by_identifier(
                incident_id
            )
        )

        if incident is None:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        return {
            "status": "success",
            "incident": incident,
        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.patch("/{incident_id}/status")
async def change_status(
    incident_id: str,
    request: IncidentStatusUpdate,
):

    try:

        incident = (
            update_incident_status(
                incident_identifier=(
                    incident_id
                ),
                status=request.status,
            )
        )

        if incident is None:

            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        return {
            "status": "success",
            "incident": incident,
        }

    except HTTPException:

        raise

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
