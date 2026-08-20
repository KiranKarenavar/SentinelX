from app.threat_intelligence.domain_enrichment import (
    enrich_domain,
)


domain = "example.com"


intelligence = [
    {
        "source": "otx",
        "confidence": 80,
        "malicious": True,
        "raw_data": {
            "pulse_info": {
                "pulses": [
                    {
                        "tags": [
                            "phishing",
                            "malware",
                        ],
                        "references": [
                            "https://example.com/report"
                        ],
                        "malware_families": [
                            "ExampleMalware"
                        ],
                    },
                    {
                        "tags": [
                            "phishing"
                        ],
                    },
                ]
            }
        },
    },
    {
        "source": "threatfox",
        "confidence": 90,
        "malicious": True,
        "raw_data": {
            "query_status": "ok",
            "data": [
                {
                    "malware_printable": "ExampleMalware",
                    "threat_actor": "ExampleActor",
                    "tags": [
                        "c2",
                        "malware",
                    ],
                }
            ],
        },
    },
]


result = enrich_domain(
    domain,
    intelligence,
)


print("=" * 60)
print("SENTINELX DOMAIN ENRICHMENT TEST")
print("=" * 60)

print()

for key, value in result.items():

    print(
        f"{key}: {value}"
    )

print()

print("=" * 60)
