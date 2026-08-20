from app.threat_intelligence.hash_enrichment import (
    enrich_hash,
)


file_hash = (
    "44d88612fea8a8f36de82e1278abb02f"
)


intelligence = [
    {
        "source": "otx",
        "confidence": 90,
        "malicious": True,
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-08-18T00:00:00Z",
        "raw_data": {
            "pulse_info": {
                "pulses": [
                    {
                        "tags": [
                            "malware",
                            "trojan",
                        ],
                        "references": [
                            "https://example.com/report"
                        ],
                        "malware_families": [
                            "ExampleTrojan"
                        ],
                    }
                ]
            }
        },
    },
    {
        "source": "threatfox",
        "confidence": 95,
        "malicious": True,
        "raw_data": {
            "query_status": "ok",
            "data": [
                {
                    "malware_printable": "ExampleTrojan",
                    "threat_actor": "ExampleActor",
                    "tags": [
                        "malware",
                        "c2",
                    ],
                }
            ],
        },
    },
]


result = enrich_hash(
    file_hash,
    "md5",
    intelligence,
)


print("=" * 60)
print("SENTINELX HASH ENRICHMENT TEST")
print("=" * 60)

print()

for key, value in result.items():

    print(
        f"{key}: {value}"
    )

print()

print("=" * 60)
