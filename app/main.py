from fastapi import FastAPI

from app.hunting.routes import router as hunting_router

from app.api.threat_intelligence import (
    router as threat_intelligence_router,
)

from app.ai.routes import (
    router as ai_router,
)

from app.dashboard.routes import (
    router as dashboard_router,
)


app = FastAPI(
    title="SentinelX",
    description=(
        "AI-Powered Cyber Threat Intelligence "
        "and SOC Platform"
    ),
    version="1.0.0",
)


app.include_router(
    hunting_router
)

app.include_router(
    threat_intelligence_router
)

app.include_router(
    ai_router
)

app.include_router(
    dashboard_router
)


@app.get("/")
async def root():

    return {
        "application": "SentinelX",
        "status": "running",
        "version": "1.0.0",
    }
