from app.threat_intelligence.enrichment import enrich_ip


intelligence = [
    {
        "source": "otx",
        "confidence": None,
        "malicious": None,
        "raw_data": {
            "reputation": 0,
            "country_code2": "US",
            "asn": "AS15169 Google LLC",
            "pulse_info": {
                "pulses": []
            }
        }
    },
    {
        "source": "abuseipdb",
        "confidence": 0,
        "malicious": False,
        "raw_data": {
            "data": {
                "countryCode": "US",
                "isp": "Google LLC",
                "domain": "google.com",
                "hostnames": [
                    "dns.google"
                ],
                "isTor": False,
                "isWhitelisted": True,
                "totalReports": 192,
                "abuseConfidenceScore": 0
            }
        }
    },
    {
        "source": "threatfox",
        "confidence": None,
        "malicious": None,
        "raw_data": {
            "query_status": "no_result"
        }
    }
]


result = enrich_ip(
    intelligence
)


print("=" * 60)
print("SENTINELX IP ENRICHMENT TEST")
print("=" * 60)

print()

for key, value in result.items():
    print(f"{key}: {value}")

print()

print("=" * 60)

