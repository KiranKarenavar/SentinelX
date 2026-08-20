from typing import Any

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    UploadFile,
)

from phishing.phishing_engine import (
    PhishingEngine,
)


router = APIRouter(
    prefix="/api/phishing",
    tags=["Phishing Investigation"],
)


engine = PhishingEngine()


@router.post("/analyze")
async def analyze_phishing_email(
    file: UploadFile = File(...),
) -> dict[str, Any]:

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required",
        )

    if not file.filename.lower().endswith(
        ".eml"
    ):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported",
        )

    try:

        file_bytes = await file.read()

        if not file_bytes:
            raise HTTPException(
                status_code=400,
                detail="Uploaded email is empty",
            )

        result = await engine.analyze(
            file_bytes,
            file.filename,
        )

        return result

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Phishing analysis failed: {exc}"
            ),
        )
