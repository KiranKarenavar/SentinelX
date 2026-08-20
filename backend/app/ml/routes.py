from typing import Any, Dict

from fastapi import (
    APIRouter,
    HTTPException,
)

from pydantic import BaseModel, Field

from app.ml.predictor import (
    ThreatPredictor,
)


router = APIRouter(
    prefix="/ml",
    tags=["Machine Learning"],
)


class MLFeatures(BaseModel):

    connection_count: int = Field(
        default=0,
        ge=0,
    )

    failed_logins: int = Field(
        default=0,
        ge=0,
    )

    suspicious_port: int = Field(
        default=0,
        ge=0,
        le=1,
    )

    known_bad_ip: int = Field(
        default=0,
        ge=0,
        le=1,
    )

    encoded_command: int = Field(
        default=0,
        ge=0,
        le=1,
    )

    privilege_escalation: int = Field(
        default=0,
        ge=0,
        le=1,
    )


predictor = ThreatPredictor()


@router.post("/predict")
async def predict_threat(
    features: MLFeatures,
) -> Dict[str, Any]:

    try:

        return predictor.predict(
            features.model_dump()
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
