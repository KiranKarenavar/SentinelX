from fastapi import APIRouter, Query

from app.hunting.engine import HuntingEngine


router = APIRouter(
    prefix="/hunting",
    tags=["Threat Hunting"]
)


hunter = HuntingEngine(
    password="Kiran-123"
)


@router.get("/all")
def hunt_all(
    size: int = Query(
        50,
        ge=1,
        le=500
    )
):

    return {
        "hunt_type": "all",
        "results": hunter.hunt(
            {"match_all": {}},
            size
        )
    }


@router.get("/ioc/{ioc}")
def hunt_ioc(
    ioc: str,
    size: int = Query(
        50,
        ge=1,
        le=500
    )
):

    return {
        "hunt_type": "ioc",
        "ioc": ioc,
        "results": hunter.hunt_ioc(
            ioc,
            size
        )
    }


@router.get("/process/{process_name}")
def hunt_process(
    process_name: str,
    size: int = Query(
        50,
        ge=1,
        le=500
    )
):

    return {
        "hunt_type": "process",
        "process": process_name,
        "results": hunter.hunt_process(
            process_name,
            size
        )
    }


@router.get("/ip/{ip}")
def hunt_ip(
    ip: str,
    size: int = Query(
        50,
        ge=1,
        le=500
    )
):

    return {
        "hunt_type": "destination_ip",
        "ip": ip,
        "results": hunter.hunt_destination_ip(
            ip,
            size
        )
    }
