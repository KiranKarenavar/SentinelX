from app.threat_intelligence.risk_engine import (
    calculate_risk_score,
)


intelligence = [
    {
        "source": "otx",
        "confidence": 70,
        "malicious": True,
    },
    {
        "source": "abuseipdb",
        "confidence": 85,
        "malicious": True,
    },
    {
        "source": "threatfox",
        "confidence": 90,
        "malicious": True,
    },
]


result = calculate_risk_score(
    intelligence
)


print("=" * 60)
print("SENTINELX RISK ENGINE TEST")
print("=" * 60)

print()

print("Risk Score:")
print(result["score"])

print()

print("Severity:")
print(result["severity"])

print()

print("Verdict:")
print(result["verdict"])

print()

print("Reasons:")

for reason in result["reasons"]:
    print("-", reason)

print()

print("Provider Scores:")

for provider in result["provider_scores"]:
    print(provider)

print()

print("=" * 60)
