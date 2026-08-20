from typing import Any, Dict

from fastapi import APIRouter

from app.threat_intelligence.storage import get_connection


router = APIRouter(
    prefix="/dashboard",
    tags=["SOC Dashboard"],
)


def safe_count(cursor, query: str) -> int:
    try:
        cursor.execute(query)
        row = cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception:
        return 0


@router.get("/summary")
async def dashboard_summary() -> Dict[str, Any]:

    connection = get_connection()

    try:
        cursor = connection.cursor()

        # =========================================
        # INCIDENTS
        # =========================================

        total_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            """
        )

        open_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(status) = 'OPEN'
            """
        )

        investigating_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(status) = 'INVESTIGATING'
            """
        )

        containment_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(status) = 'CONTAINMENT'
            """
        )

        resolved_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(status) = 'RESOLVED'
            """
        )

        # =========================================
        # SEVERITY
        # =========================================

        critical_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(severity) = 'CRITICAL'
            """
        )

        high_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(severity) = 'HIGH'
            """
        )

        medium_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(severity) = 'MEDIUM'
            """
        )

        low_incidents = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE UPPER(severity) = 'LOW'
            """
        )

        # =========================================
        # IOC STATISTICS
        # =========================================

        total_iocs = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM iocs
            """
        )

        malicious_iocs = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM iocs
            WHERE UPPER(severity) IN ('CRITICAL', 'HIGH')
            """
        )

        # =========================================
        # THREAT INTELLIGENCE
        # =========================================

        total_intelligence = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM threat_intelligence
            """
        )

        # =========================================
        # HONEYPOT
        # =========================================

        total_honeypot_events = safe_count(
            cursor,
            """
            SELECT COUNT(*)
            FROM honeypot_events
            """
        )

        # =========================================
        # RECENT INCIDENTS
        # =========================================

        recent_incidents = []

        try:
            cursor.execute(
                """
                SELECT
                    id,
                    incident_id,
                    title,
                    severity,
                    status,
                    source_ip,
                    destination_ip,
                    ioc,
                    mitre_technique,
                    created_at
                FROM incidents
                ORDER BY id DESC
                LIMIT 10
                """
            )

            rows = cursor.fetchall()

            for row in rows:
                recent_incidents.append(
                    {
                        "id": row[0],
                        "incident_id": row[1],
                        "title": row[2],
                        "severity": row[3],
                        "status": row[4],
                        "source_ip": row[5],
                        "destination_ip": row[6],
                        "ioc": row[7],
                        "mitre_technique": row[8],
                        "created_at": (
                            row[9].isoformat()
                            if row[9]
                            else None
                        ),
                    }
                )

        except Exception:
            recent_incidents = []

        cursor.close()

        return {
            "status": "success",

            "dashboard": {
                "name": "SentinelX SOC Dashboard",
                "version": "1.0",
            },

            "incidents": {
                "total": total_incidents,
                "open": open_incidents,
                "investigating": investigating_incidents,
                "containment": containment_incidents,
                "resolved": resolved_incidents,
            },

            "severity": {
                "critical": critical_incidents,
                "high": high_incidents,
                "medium": medium_incidents,
                "low": low_incidents,
            },

            "threat_intelligence": {
                "total_iocs": total_iocs,
                "malicious_iocs": malicious_iocs,
                "intelligence_records": total_intelligence,
            },

            "honeypot": {
                "total_events": total_honeypot_events,
            },

            "recent_incidents": recent_incidents,
        }

    finally:
        connection.close()
