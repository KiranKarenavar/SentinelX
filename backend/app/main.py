from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


from app.api.threat_intelligence import (
    router as threat_intelligence_router,
)

from app.ai.routes import (
    router as ai_router,
)

from app.hunting.routes import (
    router as hunting_router,
)

from app.incidents.routes import (
    router as incidents_router,
)

from app.honeypot.routes import (
    router as honeypot_router,
)

from app.ml.routes import (
    router as ml_router,
)


app = FastAPI(
    title="SentinelX",
    description=(
        "AI-Powered Cyber Threat Intelligence "
        "and SOC Platform"
    ),
    version="1.0.0",
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://10.81.171.233:5173",
    ],

    allow_credentials=True,

    allow_methods=[
        "*",
    ],

    allow_headers=[
        "*",
    ],
)


# ============================================================
# ROOT / HEALTH CHECK
# ============================================================

@app.get("/")
async def root():

    return {
        "application": "SentinelX",
        "status": "running",
        "version": "1.0.0",
    }


# ============================================================
# API ROUTERS
# ============================================================

app.include_router(
    threat_intelligence_router
)

app.include_router(
    ai_router
)

app.include_router(
    hunting_router
)

app.include_router(
    incidents_router
)

app.include_router(
    honeypot_router
)

app.include_router(
    ml_router
)
