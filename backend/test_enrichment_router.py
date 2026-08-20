from app.threat_intelligence.enrichment_router import (
    enrich_ioc,
)


test_iocs = [
    "8.8.8.8",
    "example.com",
    "https://example.com/login",
    "44d88612fea8a8f36de82e1278abb02f",
]


for ioc in test_iocs:

    result = enrich_ioc(
        ioc,
        [],
    )

    print("=" * 60)

    print(
        "IOC:",
        result["ioc"]
    )

    print(
        "Type:",
        result["ioc_type"]
    )

    print(
        "Status:",
        result.get(
            "status",
            "ready"
        )
    )
