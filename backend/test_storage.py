from app.threat_intelligence.storage import (
    store_ioc,
    store_threat_intelligence,
)


def main():

    print("Testing IOC storage...")

    ioc_id = store_ioc(
        indicator="8.8.8.8",
        indicator_type="ipv4",
        source="otx",
        confidence=0,
        severity="UNKNOWN",
    )

    print(f"IOC stored successfully. ID: {ioc_id}")

    print()
    print("Testing threat intelligence storage...")

    intelligence_id = store_threat_intelligence(
        title="OTX intelligence for 8.8.8.8",
        source="otx",
        description="AlienVault OTX intelligence record",
        threat_type="ipv4",
        severity="UNKNOWN",
        confidence=0,
        raw_data={
            "indicator": "8.8.8.8",
            "type": "IPv4",
        },
    )

    print(
        f"Threat intelligence stored successfully. "
        f"ID: {intelligence_id}"
    )


if __name__ == "__main__":
    main()
