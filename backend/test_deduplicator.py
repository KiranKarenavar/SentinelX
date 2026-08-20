from app.threat_intelligence.deduplicator import deduplicate_iocs


def main():

    results = [
        {
            "ioc_type": "ipv4",
            "value": "185.10.10.10",
            "source": "otx",
            "confidence": 70,
            "malicious": True,
        },
        {
            "ioc_type": "ipv4",
            "value": "185.10.10.10",
            "source": "abuseipdb",
            "confidence": 85,
            "malicious": True,
        },
        {
            "ioc_type": "ipv4",
            "value": "185.10.10.10",
            "source": "threatfox",
            "confidence": 90,
            "malicious": True,
        },
        {
            "ioc_type": "ipv4",
            "value": "8.8.8.8",
            "source": "otx",
            "confidence": 0,
            "malicious": False,
        },
    ]

    deduplicated = deduplicate_iocs(results)

    print("Deduplicated IOCs:")
    print()

    for ioc in deduplicated:
        print(ioc)


if __name__ == "__main__":
    main()
