from app.threat_intelligence.url_enrichment import (
    enrich_url,
)


url = "https://example.com/login"


intelligence = [
    {
        "source": "otx",
        "confidence": 85,
        "malicious": True,
        "raw_data": {
            "pulse_info": {
                "pulses": [
                    {
                        "tags": [
                            "phishing",
                            "credential-theft",
                        ],
                        "references": [
                            "https://example.com/report"
                        ],
                        "malware_families": [
                            "ExampleStealer"
                        ],
                    }
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
                    "malware_printable": "ExampleStealer",
                    "threat_actor": "ExampleActor",
                    "tags": [
                        "phishing",
                        "c2",
                    ],
                }
            ],
        },
    },
]


result = enrich_url(
    url,
    intelligence,
)


print("=" * 60)
print("SENTINELX URL ENRICHMENT TEST")
print("=" * 60)

print()

for key, value in result.items():

    print(
        f"{key}: {value}"
    )

print()

print("=" * 60)
