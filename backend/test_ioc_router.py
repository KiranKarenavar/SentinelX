from app.threat_intelligence.enrichment_router import (
    detect_ioc_type,
)


test_iocs = [
    "8.8.8.8",
    "2001:4860:4860::8888",
    "google.com",
    "https://google.com",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855",
    "this-is-not-an-ioc",
]


print("=" * 60)
print("SENTINELX UNIVERSAL IOC DETECTOR")
print("=" * 60)


for ioc in test_iocs:

    ioc_type = detect_ioc_type(ioc)

    print(
        f"IOC: {ioc}"
    )

    print(
        f"Type: {ioc_type}"
    )

    print("-" * 60)


print("IOC DETECTOR TEST COMPLETED")

