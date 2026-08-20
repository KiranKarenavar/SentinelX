from app.threat_intelligence.storage import (
    store_enrichment_result,
    get_ioc_by_id,
    get_threat_intelligence_by_id,
)


indicator = "8.8.8.8"

indicator_type = "ipv4"

risk_score = 15

severity = "LOW"

verdict = "BENIGN"


enrichment = {
    "country": "US",
    "isp": "Google LLC",
    "asn": "AS15169 Google LLC",
    "domain": "google.com",
    "hostnames": [
        "dns.google"
    ],
    "is_tor": False,
    "is_whitelisted": True,
    "total_reports": 192,
    "abuse_confidence": 0,
    "otx_reputation": 0,
    "otx_pulse_count": 0,
    "threatfox_result": "no_result",
    "malware_families": [],
    "threat_actors": [],
    "tags": [],
    "references": [],
    "confidence": 0,
}


print("=" * 60)
print("SENTINELX ENRICHMENT DATABASE TEST")
print("=" * 60)

print()

print(
    "Storing enrichment result..."
)

result = store_enrichment_result(
    indicator=indicator,
    indicator_type=indicator_type,
    risk_score=risk_score,
    severity=severity,
    verdict=verdict,
    enrichment=enrichment,
)

print()

print(
    "Stored successfully:"
)

print(result)

print()

print(
    "Retrieving IOC..."
)

ioc = get_ioc_by_id(
    result["ioc_id"]
)

print(ioc)

print()

print(
    "Retrieving threat intelligence..."
)

intelligence = (
    get_threat_intelligence_by_id(
        result["intelligence_id"]
    )
)

print(intelligence)

print()

print("=" * 60)
print("DATABASE TEST COMPLETED")
print("=" * 60)
