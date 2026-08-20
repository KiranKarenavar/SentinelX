from fastapi import (
    APIRouter,
    UploadFile,
    File,
    HTTPException,
)

from app.phishing.engine import PhishingEngine

from app.threat_intelligence.storage import (
    store_phishing_investigation,
)


router = APIRouter(
    prefix="/phishing",
    tags=["Phishing Investigation"],
)


engine = PhishingEngine()


@router.post("/analyze")
async def analyze_phishing_email(
    file: UploadFile = File(...)
):

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file provided",
        )

    if not file.filename.lower().endswith(
        ".eml"
    ):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported",
        )

    raw_email = await file.read()

    if not raw_email:

        raise HTTPException(
            status_code=400,
            detail="Empty email file",
        )

    try:

        result = await engine.investigate(
            raw_email
        )

        stored = store_phishing_investigation(
            filename=file.filename,
            result=result,
        )

        return {
            "status": "success",
            "filename": file.filename,
            "investigation": stored,
            **result,
        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
