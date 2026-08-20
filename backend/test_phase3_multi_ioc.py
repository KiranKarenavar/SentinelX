import json
import httpx


BASE_URL = "http://127.0.0.1:8000"


TEST_IOCS = [
    {
        "type": "IPv4",
        "value": "8.8.8.8",
    },
    {
        "type": "Domain",
        "value": "example.com",
    },
    {
        "type": "URL",
        "value": "https://example.com",
    },
    {
        "type": "SHA256",
        "value": (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),
    },
]


def test_ioc(ioc_type, value):

    print()
    print("=" * 60)
    print(f"IOC TYPE : {ioc_type}")
    print(f"IOC      : {value}")
    print("=" * 60)

    # Current Phase 3 API endpoint
    url = (
        f"{BASE_URL}"
        f"/api/threat-intelligence/analyze/"
        f"{value}"
    )

    try:

        response = httpx.get(
            url,
            timeout=120.0,
        )

        print()
        print("HTTP STATUS:")
        print(response.status_code)

        if response.status_code != 200:

            print()
            print("API ERROR:")
            print(response.text)

            return

        result = response.json()

        print()
        print("RESULT:")

        print(
            json.dumps(
                result,
                indent=4,
            )
        )

        # Try to find risk information
        risk = result.get(
            "risk",
            {},
        )

        if isinstance(
            risk,
            dict,
        ):

            print()
            print("RISK SUMMARY:")
            print(
                "Score:",
                risk.get(
                    "score",
                    risk.get(
                        "risk_score",
                        "N/A",
                    ),
                ),
            )

            print(
                "Severity:",
                risk.get(
                    "severity",
                    "N/A",
                ),
            )

            print(
                "Verdict:",
                risk.get(
                    "verdict",
                    "N/A",
                ),
            )

    except Exception as error:

        print()
        print("REQUEST FAILED:")
        print(error)


def main():

    print("=" * 60)
    print("SENTINELX PHASE 3")
    print("MULTI-IOC TEST")
    print("=" * 60)

    print()
    print(
        f"Testing {len(TEST_IOCS)} IOC types..."
    )

    for item in TEST_IOCS:

        test_ioc(
            item["type"],
            item["value"],
        )

    print()
    print("=" * 60)
    print("MULTI-IOC TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
