from datetime import datetime, timezone
from typing import Any, Dict, Optional

from psycopg2.extras import Json

from app.threat_intelligence.storage import (
    get_connection,
)


def _generate_incident_id(
    connection,
) -> str:

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COALESCE(
            MAX(id),
            0
        ) + 1
        FROM incidents
        """
    )

    number = cursor.fetchone()[0]

    cursor.close()

    return f"INC-{number:04d}"


def create_incident(
    title: str,
    description: str = "",
    severity: str = "MEDIUM",
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    ioc: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        incident_id = _generate_incident_id(
            connection
        )

        now = datetime.now(
            timezone.utc
        )

        cursor.execute(
            """
            INSERT INTO incidents (
                incident_id,
                title,
                description,
                severity,
                status,
                source_ip,
                destination_ip,
                ioc,
                mitre_technique,
                evidence,
                created_at,
                updated_at
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            )
            RETURNING id
            """,
            (
                incident_id,
                title,
                description,
                str(
                    severity
                ).upper(),
                "OPEN",
                source_ip,
                destination_ip,
                ioc,
                mitre_technique,
                Json(
                    evidence or {}
                ),
                now,
                now,
            ),
        )

        incident_db_id = (
            cursor.fetchone()[0]
        )

        connection.commit()

        cursor.close()

        return get_incident(
            incident_db_id
        )

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


def get_incident(
    incident_id: int,
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                incident_id,
                title,
                description,
                severity,
                status,
                source_ip,
                destination_ip,
                ioc,
                mitre_technique,
                evidence,
                created_at,
                updated_at
            FROM incidents
            WHERE id = %s
            """,
            (
                incident_id,
            ),
        )

        row = cursor.fetchone()

        cursor.close()

        if row is None:
            return None

        return _row_to_dict(
            row
        )

    finally:

        connection.close()


def get_incident_by_identifier(
    incident_identifier: str,
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                incident_id,
                title,
                description,
                severity,
                status,
                source_ip,
                destination_ip,
                ioc,
                mitre_technique,
                evidence,
                created_at,
                updated_at
            FROM incidents
            WHERE incident_id = %s
            """,
            (
                incident_identifier,
            ),
        )

        row = cursor.fetchone()

        cursor.close()

        if row is None:
            return None

        return _row_to_dict(
            row
        )

    finally:

        connection.close()


def list_incidents(
    limit: int = 50,
):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                incident_id,
                title,
                description,
                severity,
                status,
                source_ip,
                destination_ip,
                ioc,
                mitre_technique,
                evidence,
                created_at,
                updated_at
            FROM incidents
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (
                limit,
            ),
        )

        rows = cursor.fetchall()

        cursor.close()

        return [
            _row_to_dict(row)
            for row in rows
        ]

    finally:

        connection.close()


def update_incident_status(
    incident_identifier: str,
    status: str,
):

    allowed_statuses = {
        "OPEN",
        "INVESTIGATING",
        "CONTAINMENT",
        "RESOLVED",
    }

    status = str(
        status
    ).upper()

    if status not in allowed_statuses:

        raise ValueError(
            "Invalid incident status"
        )

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE incidents
            SET
                status = %s,
                updated_at = %s
            WHERE incident_id = %s
            RETURNING
                id,
                incident_id,
                title,
                description,
                severity,
                status,
                source_ip,
                destination_ip,
                ioc,
                mitre_technique,
                evidence,
                created_at,
                updated_at
            """,
            (
                status,
                datetime.now(
                    timezone.utc
                ),
                incident_identifier,
            ),
        )

        row = cursor.fetchone()

        if row is None:

            connection.rollback()

            return None

        connection.commit()

        cursor.close()

        return _row_to_dict(
            row
        )

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


def _row_to_dict(
    row,
):

    return {
        "id": row[0],
        "incident_id": row[1],
        "title": row[2],
        "description": row[3],
        "severity": row[4],
        "status": row[5],
        "source_ip": row[6],
        "destination_ip": row[7],
        "ioc": row[8],
        "mitre_technique": row[9],
        "evidence": row[10] or {},
        "created_at": (
            row[11].isoformat()
            if row[11]
            else None
        ),
        "updated_at": (
            row[12].isoformat()
            if row[12]
            else None
        ),
    }
