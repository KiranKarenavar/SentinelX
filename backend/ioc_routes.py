from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import IOC


router = APIRouter(
    prefix="/api/iocs",
    tags=["IOCs"],
)


class IOCCreate(BaseModel):
    indicator: str
    indicator_type: str
    source: str
    confidence: int = 0
    severity: str = "MEDIUM"
    malware_family: str | None = None
    threat_actor: str | None = None
    mitre_technique: str | None = None


@router.post("/")
def create_ioc(
    ioc_data: IOCCreate,
    db: Session = Depends(get_db),
):
    ioc = IOC(
        indicator=ioc_data.indicator,
        indicator_type=ioc_data.indicator_type,
        source=ioc_data.source,
        confidence=ioc_data.confidence,
        severity=ioc_data.severity,
        malware_family=ioc_data.malware_family,
        threat_actor=ioc_data.threat_actor,
        mitre_technique=ioc_data.mitre_technique,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )

    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    return {
        "message": "IOC created successfully",
        "id": ioc.id,
        "indicator": ioc.indicator,
    }


@router.get("/")
def get_iocs(
    db: Session = Depends(get_db),
):
    iocs = db.query(IOC).order_by(IOC.created_at.desc()).all()

    return iocs
