import re
import psycopg2
from datetime import datetime, timezone


DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5432,
    "database": "sentinelx",
    "user": "sentinelx_app",
    "password": "SentinelX_DB_2026!",
}


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def extract_ips(text):
    if not text:
        return []

    return IP_PATTERN.findall(text)


def is_valid_ip(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    return all(
        part.isdigit() and 0 <= int(part) <= 255
        for part in parts
    )


def main():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            payload,
            raw_data
        FROM honeypot_events
    """)

    events = cursor.fetchall()

    found_ips = set()

    for source_ip, destination_ip, payload, raw_data in events:

        values = [
            source_ip,
            destination_ip,
            payload,
            str(raw_data) if raw_data else ""
        ]

        for value in values:
            for ip in extract_ips(value):

                if is_valid_ip(ip):
                    found_ips.add(ip)

    print(f"Found {len(found_ips)} unique IP(s).")

    now = datetime.now(timezone.utc)

    inserted = 0
    existing = 0

    for ip in sorted(found_ips):

        cursor.execute(
            """
            SELECT id
            FROM iocs
            WHERE indicator = %s
              AND indicator_type = %s
              AND source = %s
            """,
            (
                ip,
                "IP",
                "Cowrie",
            ),
        )

        existing_ioc = cursor.fetchone()

        if existing_ioc:
            existing += 1

            cursor.execute(
                """
                UPDATE iocs
                SET last_seen = %s
                WHERE id = %s
                """,
                (
                    now,
                    existing_ioc[0],
                ),
            )

            continue

        cursor.execute(
            """
            INSERT INTO iocs
            (
                indicator,
                indicator_type,
                source,
                confidence,
                severity,
                first_seen,
                last_seen,
                malware_family,
                threat_actor,
                mitre_technique,
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
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                ip,
                "IP",
                "Cowrie",
                50,
                "MEDIUM",
                now,
                now,
                None,
                None,
                None,
                now,
            ),
        )

        inserted += 1

    connection.commit()

    cursor.close()
    connection.close()

    print(f"Inserted IOCs: {inserted}")
    print(f"Existing IOCs: {existing}")


if __name__ == "__main__":
    main()
