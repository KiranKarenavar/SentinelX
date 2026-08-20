from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class HoneypotEvent(BaseModel):

    source_ip: str

    destination_ip: Optional[str] = None

    destination_port: Optional[int] = None

    protocol: Optional[str] = None

    username: Optional[str] = None

    event_type: str = "connection"

    payload: Optional[str] = None

    severity: str = "MEDIUM"

    timestamp: Optional[str] = None

    raw_data: Dict[str, Any] = Field(
        default_factory=dict
    )
