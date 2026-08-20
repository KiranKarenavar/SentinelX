from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from database import get_db
from ioc_routes import router as ioc_router
from intelligence_routes import router as intelligence_router
from wazuh_routes import router as wazuh_router
from hunt.routes import router as hunt_router
from phishing.routes import router as phishing_router
from ml.predict import analyze_event
from ai_agent.analyzer import SOCAnalyzer
from fastapi.middleware.cors import CORSMiddleware
from incident_routes import router as incident_router

app = FastAPI(
    title="SentinelX API",
    description="Cyber Threat Intelligence and SOC Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(ioc_router)
app.include_router(intelligence_router)
app.include_router(wazuh_router)
app.include_router(hunt_router)
app.include_router(phishing_router)
ai_analyzer = SOCAnalyzer()
app.include_router(incident_router)

@app.get("/")
def root():
    return {
        "project": "SentinelX",
        "status": "online",
    }


@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
        }

    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
        }

@app.post("/api/ml/analyze")
def ml_analyze(event: dict):
    try:
        return analyze_event(event)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"ML analysis failed: {str(e)}"
        )


@app.post("/api/ai/investigate")
def ai_investigate(evidence: dict):

    try:
        return ai_analyzer.investigate(evidence)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"AI investigation failed: {str(e)}"
        )


@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    try:
        alerts = db.execute(
            text("SELECT COUNT(*) FROM alerts")
        ).scalar()

        critical = db.execute(
            text("""
                SELECT COUNT(*)
                FROM alerts
                WHERE LOWER(severity) = 'critical'
            """)
        ).scalar()

        iocs = db.execute(
            text("SELECT COUNT(*) FROM iocs")
        ).scalar()

        incidents = db.execute(
            text("SELECT COUNT(*) FROM incidents")
        ).scalar()

        hunts = db.execute(
            text("SELECT COUNT(*) FROM hunting_queries")
        ).scalar()

        return {
            "alerts": alerts,
            "critical": critical,
            "iocs": iocs,
            "incidents": incidents,
            "hunts": hunts
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Dashboard statistics failed: {str(e)}"
        )


@app.get("/api/dashboard/recent-alerts")
def recent_alerts(db: Session = Depends(get_db)):
    try:
        result = db.execute(
            text("""
                SELECT
                    id,
                    title,
                    description,
                    severity,
                    status,
                    source,
                    mitre_technique,
                    created_at
                FROM alerts
                ORDER BY created_at DESC
                LIMIT 10
            """)
        )

        alerts = []

        for row in result:
            alerts.append({
                "id": row.id,
                "title": row.title,
                "description": row.description,
                "severity": row.severity,
                "status": row.status,
                "source": row.source,
                "mitre_technique": row.mitre_technique,
                "created_at": row.created_at.isoformat()
                if row.created_at else None
            })

        return {
            "count": len(alerts),
            "alerts": alerts
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch alerts: {str(e)}"
        )


@app.get("/api/incidents")
def get_incidents(db: Session = Depends(get_db)):
    try:
        result = db.execute(
            text("""
                SELECT
                    id,
                    title,
                    description,
                    severity,
                    status,
                    assigned_to,
                    created_at,
                    updated_at
                FROM incidents
                ORDER BY created_at DESC
                LIMIT 50
            """)
        )

        incidents = []

        for row in result:
            incidents.append({
                "id": row.id,
                "incident_id": f"INC-{row.id:04d}",
                "title": row.title,
                "description": row.description,
                "severity": row.severity,
                "status": row.status,
                "assigned_to": row.assigned_to,
                "created_at": row.created_at.isoformat()
                if row.created_at else None,
                "updated_at": row.updated_at.isoformat()
                if row.updated_at else None
            })

        return {
            "count": len(incidents),
            "incidents": incidents
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch incidents: {str(e)}"
        )


@app.post("/api/incidents")
def create_incident(incident: dict, db: Session = Depends(get_db)):
    try:
        result = db.execute(
            text("""
                INSERT INTO incidents
                (
                    title,
                    description,
                    severity,
                    status,
                    created_at,
                    updated_at
                )
                VALUES
                (
                    :title,
                    :description,
                    :severity,
                    :status,
                    NOW(),
                    NOW()
                )
                RETURNING id
            """),
            {
                "title": incident.get("title"),
                "description": incident.get("description"),
                "severity": incident.get("severity", "MEDIUM"),
                "status": incident.get("status", "OPEN")
            }
        )

        incident_id = result.scalar()
        db.commit()

        return {
            "message": "Incident created",
            "incident_id": f"INC-{incident_id:04d}",
            "id": incident_id
        }

    except Exception as e:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Failed to create incident: {str(e)}"
        )


@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    data: dict,
    db: Session = Depends(get_db)
):
    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "CONTAINMENT",
        "RESOLVED"
    ]

    status = data.get("status")

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Use one of: {allowed_statuses}"
        )

    try:
        result = db.execute(
            text("""
                UPDATE incidents
                SET
                    status = :status,
                    updated_at = NOW()
                WHERE id = :id
                RETURNING id
            """),
            {
                "status": status,
                "id": incident_id
            }
        )

        updated = result.scalar()

        if updated is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found"
            )

        db.commit()

        return {
            "message": "Incident status updated",
            "incident_id": f"INC-{incident_id:04d}",
            "status": status
        }

    except HTTPException:
        raise

    except Exception as e:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Failed to update incident: {str(e)}"
        )


@app.get("/api/dashboard/alerts")
def dashboard_alerts(db: Session = Depends(get_db)):

    result = db.execute(
        text("""
            SELECT
                id,
                title,
                severity,
                status,
                source,
                mitre_technique,
                created_at
            FROM alerts
            ORDER BY id DESC
            LIMIT 10
        """)
    )

    alerts = []

    for row in result:
        alerts.append({
            "id": row.id,
            "title": row.title,
            "severity": row.severity,
            "status": row.status,
            "source": row.source,
            "mitre_technique": row.mitre_technique,
            "created_at": str(row.created_at)
        })

    return alerts


@app.get("/api/dashboard/iocs")
def dashboard_iocs(db: Session = Depends(get_db)):

    result = db.execute(
        text("""
            SELECT
                id,
                indicator,
                indicator_type,
                source,
                confidence,
                severity
            FROM iocs
            ORDER BY id DESC
            LIMIT 10
        """)
    )

    iocs = []

    for row in result:
        iocs.append({
            "id": row.id,
            "indicator": row.indicator,
            "indicator_type": row.indicator_type,
            "source": row.source,
            "confidence": row.confidence,
            "severity": row.severity
        })

    return iocs



@app.get("/api/dashboard/mitre")
def dashboard_mitre(db: Session = Depends(get_db)):

    result = db.execute(
        text("""
            SELECT
                mitre_technique,
                COUNT(*) AS count
            FROM alerts
            WHERE mitre_technique IS NOT NULL
            GROUP BY mitre_technique
            ORDER BY count DESC
            LIMIT 10
        """)
    )

    techniques = []

    for row in result:
        techniques.append({
            "technique": row.mitre_technique,
            "count": row.count
        })

    return techniques
