import json
import os
import hashlib
import psycopg2


COWRIE_LOG = "/home/kiran/sentinelx/data/honeypot/cowrie.json"


DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5432,
    "database": "sentinelx",
    "user": "sentinelx_app",
    "password": "SentinelX_DB_2026!",
}


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


def ingest_cowrie_events():
    if not os.path.exists(COWRIE_LOG):
        print(f"Cowrie log not found: {COWRIE_LOG}")
        return

    connection = get_db_connection()
    cursor = connection.cursor()

    inserted = 0
    skipped = 0

    with open(COWRIE_LOG, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_hash = hashlib.sha256(
                json.dumps(event, sort_keys=True).encode("utf-8")
            ).hexdigest()

            timestamp = event.get("timestamp")

            source_ip = (
                event.get("src_ip")
                or event.get("src_ip_address")
                or event.get("peerIP")
                or "unknown"
            )

            destination_ip = event.get("dst_ip")
            destination_port = event.get("dst_port")

            protocol = event.get("protocol")
            username = event.get("username")

            event_type = (
                event.get("eventid")
                or event.get("event_type")
            )

            payload = (
                event.get("input")
                or event.get("message")
                or event.get("command")
            )

            severity = "MEDIUM"

            cursor.execute(
                """
                INSERT INTO honeypot_events
                (
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
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_hash) DO NOTHING
                """,
                (
                    timestamp,
                    source_ip,
                    destination_ip,
                    destination_port,
                    protocol,
                    username,
                    event_type,
                    payload,
                    severity,
                    json.dumps(event),
                    event_hash,
                ),
            )

            if cursor.rowcount == 1:
                inserted += 1
            else:
                skipped += 1

    connection.commit()

    cursor.close()
    connection.close()

    print(f"Inserted: {inserted}")
    print(f"Skipped duplicates: {skipped}")


if __name__ == "__main__":
    ingest_cowrie_events()
