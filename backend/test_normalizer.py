from app.threat_intelligence.normalizer import normalize_threatfox_ioc


def main():

    threatfox_response = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "185.10.10.10",
                "ioc_type": "ip:port",
                "confidence_level": 90,
                "first_seen": "2026-08-01 10:00:00",
                "last_seen": "2026-08-15 12:00:00",
                "tags": [
                    "malware",
                    "c2"
                ],
            }
        ],
    }

    result = normalize_threatfox_ioc(
        ioc_value="185.10.10.10",
        raw_data=threatfox_response,
    )

    print("ThreatFox Normalized IOC:")
    print(result)


if __name__ == "__main__":
    main()
