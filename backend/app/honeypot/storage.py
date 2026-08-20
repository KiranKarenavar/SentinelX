import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict

import psycopg2
from psycopg2.extras import Json

from app.config import DATABASE_URL


def get_connection():
    return psycopg2.connect(
        DATABASE_URL
    )


def _event_hash(event: Dict[str, Any]) -> str:
    """
    Create a deterministic hash for a honeypot event.
    """

    hash_data = {
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get(
            "destination_ip"
        ),
        "destination_port": event.get(
            "destination_port"
        ),
        "protocol": event.get("protocol"),
        "username": event.get("username"),
        "event_type": event.get(
            "event_type"
        ),
        "payload": event.get("payload"),
    }

    serialized = json.dumps(
        hash_data,
        sort_keys=True,
        default=str,
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def store_honeypot_event(
    event: Dict[str, Any],
):
    """
    Store a honeypot event using the existing
    SentinelX honeypot_events schema.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        event_hash = _event_hash(event)

        timestamp = event.get(
            "timestamp"
        )

        if not timestamp:

            timestamp = datetime.now(
                timezone.utc
            )

        payload = event.get(
            "payload"
        )

        if payload is None:

            payload = event.get(
                "command",
                ""
            )

        raw_data = event.get(
            "raw_data"
        )

        if raw_data is None:

            raw_data = event.get(
                "metadata",
                {}
            )

        query = """
            INSERT INTO honeypot_events (
                timestamp,
                source_ip,
                destination_ip,
                destination_port,
                protocol,
                username,
                event_type,
                payload,
                severity,
                raw_data,
                event_hash
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (event_hash)
            DO NOTHING
            RETURNING id
        """

        cursor.execute(
            query,
            (
                timestamp,
                event.get(
                    "source_ip"
                ),
                event.get(
                    "destination_ip"
                ),
                event.get(
                    "destination_port"
                ),
                event.get(
                    "protocol"
                ),
                event.get(
                    "username"
                ),
                event.get(
                    "event_type",
                    "connection",
                ),
                payload,
                event.get(
                    "severity",
                    "MEDIUM",
                ),
                Json(raw_data),
                event_hash,
            ),
        )

        row = cursor.fetchone()

        if row:

            event_id = row[0]

            connection.commit()

            status = "stored"

        else:

            connection.commit()

            cursor.execute(
                """
                SELECT id
                FROM honeypot_events
                WHERE event_hash = %s
                """,
                (event_hash,),
            )

            existing = cursor.fetchone()

            event_id = (
                existing[0]
                if existing
                else None
            )

            status = "duplicate"

        cursor.close()

        return {
            "id": event_id,
            "status": status,
            "event_hash": event_hash,
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


def get_recent_honeypot_events(
    limit: int = 20,
):
    """
    Retrieve recent honeypot events.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                timestamp,
                source_ip,
                destination_ip,
                destination_port,
                protocol,
                username,
                event_type,
                payload,
                severity,
                raw_data,
                event_hash
            FROM honeypot_events
            ORDER BY timestamp DESC
            LIMIT %s
            """,
            (limit,),
        )

        rows = cursor.fetchall()

        cursor.close()

        results = []

        for row in rows:

            results.append(
                {
                    "id": row[0],
                    "timestamp": (
                        row[1].isoformat()
                        if row[1]
                        else None
                    ),
                    "source_ip": row[2],
                    "destination_ip": row[3],
                    "destination_port": row[4],
                    "protocol": row[5],
                    "username": row[6],
                    "event_type": row[7],
                    "payload": row[8],
                    "severity": row[9],
                    "raw_data": row[10],
                    "event_hash": row[11],
                }
            )

        return results

    finally:

        connection.close()
