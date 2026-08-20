from pydantic import BaseModel
from typing import List, Optional


class IOCEvidence(BaseModel):
    indicator: str
    indicator_type: str
    source: Optional[str] = None
    confidence: Optional[int] = None
    severity: Optional[str] = None
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    mitre_technique: Optional[str] = None


class AlertEvidence(BaseModel):
    alert_id: Optional[str] = None
    rule_id: Optional[str] = None
    description: Optional[str] = None
    level: Optional[int] = None
    agent: Optional[str] = None
    srcip: Optional[str] = None
    mitre_techniques: List[str] = []


class InvestigationEvidence(BaseModel):
    alert: AlertEvidence
    iocs: List[IOCEvidence] = []
    logs: List[dict] = []
    threat_intelligence: List[dict] = []
    detection_rules: List[dict] = []
    risk_score: Optional[int] = None
