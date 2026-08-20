import pandas as pd


FEATURE_COLUMNS = [
    "failed_logins",
    "connection_count",
    "unique_ips",
    "unique_destinations",
    "bytes_sent",
    "bytes_received",
    "process_count",
]


def build_features(events):
    """
    Convert security events into numerical ML features.
    """

    if not events:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    rows = []

    for event in events:
        rows.append({
            "failed_logins": int(event.get("failed_logins", 0)),
            "connection_count": int(event.get("connection_count", 0)),
            "unique_ips": int(event.get("unique_ips", 0)),
            "unique_destinations": int(
                event.get("unique_destinations", 0)
            ),
            "bytes_sent": int(event.get("bytes_sent", 0)),
            "bytes_received": int(event.get("bytes_received", 0)),
            "process_count": int(event.get("process_count", 0)),
        })

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
