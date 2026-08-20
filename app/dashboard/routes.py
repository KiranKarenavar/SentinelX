from typing import Any, Dict

from fastapi import APIRouter

from app.threat_intelligence.storage import get_connection


router = APIRouter(
    prefix="/dashboard",
    tags=["SOC Dashboard"],
)


@router.get("/summary")
async def dashboard_summary() -> Dict[str, Any]:

    connection = get_connection()

    try:

        cursor = connection.cursor()

        # =========================================
        # INCIDENT COUNTS
        # =========================================

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            """
        )

        total_incidents = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE status = 'OPEN'
            """
        )

        open_incidents = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE status = 'INVESTIGATING'
            """
        )

        investigating = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE severity = 'CRITICAL'
            """
        )

        critical_incidents = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE severity = 'HIGH'
            """
        )

        high_incidents = cursor.fetchone()[0]

        # =========================================
        # IOC COUNTS
        # =========================================

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM iocs
            """
        )

        total_iocs = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM iocs
            WHERE severity IN ('HIGH', 'CRITICAL')
            """
        )

        malicious_iocs = cursor.fetchone()[0]

        # =========================================
        # HONEYPOT EVENTS
        # =========================================

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM honeypot_events
            """
        )

        honeypot_events = cursor.fetchone()[0]

        # =========================================
        # THREAT INTELLIGENCE
        # =========================================

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM threat_intelligence
            """
        )

        intelligence_records = cursor.fetchone()[0]

        cursor.close()

        return {
            "status": "success",

            "incidents": {
                "total": total_incidents,
                "open": open_incidents,
                "investigating": investigating,
                "critical": critical_incidents,
                "high": high_incidents,
            },

            "threat_intelligence": {
                "total_iocs": total_iocs,
                "high_risk_iocs": malicious_iocs,
                "records": intelligence_records,
            },

            "honeypot": {
                "events": honeypot_events,
            },
        }

    finally:

        connection.close()
