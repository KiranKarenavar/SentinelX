from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("")
def get_incidents(db: Session = Depends(get_db)):
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
            ORDER BY id DESC
        """)
    )

    incidents = []

    for row in result:
        incidents.append({
            "id": row.id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "status": row.status,
            "assigned_to": row.assigned_to,
            "created_at": str(row.created_at),
            "updated_at": str(row.updated_at)
        })

    return incidents


@router.post("")
def create_incident(data: dict, db: Session = Depends(get_db)):

    title = data.get("title")
    description = data.get("description")
    severity = data.get("severity", "MEDIUM")

    if not title:
        raise HTTPException(
            status_code=400,
            detail="Incident title is required"
        )

    result = db.execute(
        text("""
            INSERT INTO incidents
            (title, description, severity, status, created_at, updated_at)
            VALUES
            (:title, :description, :severity, 'OPEN', NOW(), NOW())
            RETURNING id
        """),
        {
            "title": title,
            "description": description,
            "severity": severity
        }
    )

    incident_id = result.scalar()

    db.commit()

    return {
        "incident_id": incident_id,
        "incident_number": f"INC-{incident_id:04d}",
        "status": "OPEN",
        "severity": severity
    }


@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    data: dict,
    db: Session = Depends(get_db)
):

    new_status = data.get("status")

    allowed = [
        "OPEN",
        "INVESTIGATING",
        "CONTAINMENT",
        "RESOLVED"
    ]

    if new_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Use: {allowed}"
        )

    result = db.execute(
        text("""
            UPDATE incidents
            SET status = :status,
                updated_at = NOW()
            WHERE id = :id
            RETURNING id
        """),
        {
            "status": new_status,
            "id": incident_id
        }
    )

    if result.scalar() is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    db.commit()

    return {
        "incident_id": incident_id,
        "status": new_status
    }
