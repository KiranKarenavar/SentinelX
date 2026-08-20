import psycopg2
from datetime import datetime, timezone

from app.config import DATABASE_URL
from app.wazuh.ingest import WazuhAlertIngestor


def get_connection():
    return psycopg2.connect(DATABASE_URL)


def map_severity(rule_level):
    """
    Convert Wazuh rule level into SentinelX severity.
    """

    try:
        level = int(rule_level)
    except (TypeError, ValueError):
        level = 0

    if level >= 12:
        return "CRITICAL"
    elif level >= 10:
        return "HIGH"
    elif level >= 7:
        return "MEDIUM"
    elif level >= 4:
        return "LOW"
    else:
        return "INFO"


def store_wazuh_alert(alert):
    """
    Store one normalized Wazuh alert in SentinelX alerts table.
    """

    title = alert.get("rule_description") or "Wazuh Alert"

    description = (
        f"Wazuh Rule ID: {alert.get('rule_id')}\n"
        f"Agent: {alert.get('agent_name')}\n"
        f"Agent IP: {alert.get('agent_ip')}\n"
        f"Decoder: {alert.get('decoder')}\n"
        f"Location: {alert.get('location')}\n"
        f"Timestamp: {alert.get('timestamp')}"
    )

    severity = map_severity(alert.get("rule_level"))

    source = "Wazuh"

    status = "NEW"

    created_at = datetime.now(timezone.utc)

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO alerts
            (
                title,
                description,
                severity,
                status,
                source,
                mitre_technique,
                assigned_to,
                created_at
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                title,
                description,
                severity,
                status,
                source,
                None,
                None,
                created_at,
            ),
        )

        alert_id = cursor.fetchone()[0]

        connection.commit()

        cursor.close()

        return alert_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def store_latest_wazuh_alerts(limit=5):
    """
    Read latest Wazuh alerts and store them in SentinelX.
    """

    ingestor = WazuhAlertIngestor()

    alerts = ingestor.get_normalized_alerts(limit=limit)

    stored = []

    for alert in alerts:
        alert_id = store_wazuh_alert(alert)

        stored.append(
            {
                "sentinelx_alert_id": alert_id,
                "wazuh_rule_id": alert.get("rule_id"),
                "severity": map_severity(alert.get("rule_level")),
                "title": alert.get("rule_description"),
            }
        )

    return stored


if __name__ == "__main__":
    print("=" * 70)
    print("SENTINELX WAZUH → POSTGRESQL STORAGE TEST")
    print("=" * 70)

    try:
        results = store_latest_wazuh_alerts(limit=5)

        print(f"\nStored alerts: {len(results)}")

        for result in results:
            print("\n----------------------------------------")
            print(f"SentinelX Alert ID : {result['sentinelx_alert_id']}")
            print(f"Wazuh Rule ID      : {result['wazuh_rule_id']}")
            print(f"Severity           : {result['severity']}")
            print(f"Title              : {result['title']}")

        print("\nSUCCESS: Wazuh alerts stored in PostgreSQL.")

    except Exception as error:
        print("\nERROR:")
        print(error)
