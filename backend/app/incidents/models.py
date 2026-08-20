from typing import Optional

from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    title: str

    description: str = ""

    severity: str = "MEDIUM"

    source_ip: Optional[str] = None

    destination_ip: Optional[str] = None

    ioc: Optional[str] = None

    mitre_technique: Optional[str] = None

    evidence: dict = Field(
        default_factory=dict
    )


class IncidentStatusUpdate(BaseModel):
    status: str


class IncidentResponse(BaseModel):
    id: int

    incident_id: str

    title: str

    description: str

    severity: str

    status: str

    source_ip: Optional[str]

    destination_ip: Optional[str]

    ioc: Optional[str]

    mitre_technique: Optional[str]

    evidence: dict

    created_at: str

    updated_at: str
