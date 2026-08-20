from app.threat_intelligence.enrichment import enrich_ip
from app.threat_intelligence.risk_engine import (
    calculate_risk_score,
)


intelligence = [
    {
        "source": "otx",
        "confidence": 90,
        "malicious": True,
        "raw_data": {
            "reputation": 5,
            "country_code2": "RU",
            "asn": "AS12345",
            "pulse_info": {
                "pulses": [
                    {},
                    {},
                    {},
                    {},
                    {},
                ]
            }
        }
    },
    {
        "source": "abuseipdb",
        "confidence": 95,
        "malicious": True,
        "raw_data": {
            "data": {
                "countryCode": "RU",
                "isp": "Malicious ISP",
                "domain": "evil.example",
                "hostnames": [
                    "evil.example"
                ],
                "isTor": True,
                "isWhitelisted": False,
                "totalReports": 500,
                "abuseConfidenceScore": 95,
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
    },
]


enrichment = enrich_ip(
    intelligence
)


risk = calculate_risk_score(
    intelligence,
    enrichment,
)


print("=" * 60)
print("SENTINELX ADVANCED RISK TEST")
print("=" * 60)

print()

print("Risk Score:")
print(risk["score"])

print()

print("Severity:")
print(risk["severity"])

print()

print("Verdict:")
print(risk["verdict"])

print()

print("Risk Factors:")

for reason in risk["reasons"]:
    print(
        "-",
        reason
    )

print()

print("=" * 60)
