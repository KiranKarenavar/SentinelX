from app.threat_intelligence.analyzer import analyze_ip


intelligence = [
    {
        "source": "otx",
        "confidence": 70,
        "malicious": True,
        "raw_data": {
            "reputation": 5,
            "country_code2": "RU",
            "asn": "AS12345 Example ASN",
            "pulse_info": {
                "pulses": [
                    {
                        "malware_families": [
                            "ExampleMalware"
                        ]
                    }
                ]
            }
        }
    },
    {
        "source": "abuseipdb",
        "confidence": 85,
        "malicious": True,
        "raw_data": {
            "data": {
                "countryCode": "RU",
                "isp": "Example ISP",
                "domain": "example.com",
                "hostnames": [
                    "malicious.example.com"
                ],
                "isTor": False,
                "isWhitelisted": False,
                "totalReports": 150,
                "abuseConfidenceScore": 85
            }
        }
    },
    {
        "source": "threatfox",
        "confidence": 90,
        "malicious": True,
        "raw_data": {
            "query_status": "ok"
        }
    }
]


result = analyze_ip(
    intelligence
)


print("=" * 60)
print("SENTINELX IOC ANALYSIS")
print("=" * 60)

print()

print("ENRICHMENT")
print("-" * 60)

for key, value in result["enrichment"].items():
    print(f"{key}: {value}")

print()

print("RISK")
print("-" * 60)

print(
    "Score:",
    result["risk"]["score"]
)

print(
    "Severity:",
    result["risk"]["severity"]
)

print(
    "Verdict:",
    result["risk"]["verdict"]
)

print()

print("Reasons:")

for reason in result["risk"]["reasons"]:
    print("-", reason)

print()

print("Provider Scores:")

for provider in result["risk"]["provider_scores"]:
    print(provider)

print()

print("=" * 60)

