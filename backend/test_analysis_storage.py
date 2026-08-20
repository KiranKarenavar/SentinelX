from app.threat_intelligence.storage import (
    store_analysis_result,
    get_latest_analysis,
)


def main():

    print("=" * 60)
    print("SENTINELX PHASE 3 ANALYSIS STORAGE TEST")
    print("=" * 60)

    indicator = "8.8.8.8"

    risk_result = {
        "score": 0,
        "risk_score": 0,
        "severity": "INFO",
        "verdict": "BENIGN",
        "reasons": [
            "No malicious evidence was reported"
        ],
        "provider_scores": [
            {
                "source": "otx",
                "score": 0,
                "confidence": 0,
                "malicious": False,
            },
            {
                "source": "abuseipdb",
                "score": 0,
                "confidence": 0,
                "malicious": False,
            },
            {
                "source": "threatfox",
                "score": 0,
                "confidence": 0,
                "malicious": False,
            },
        ],
    }

    intelligence_results = [
        {
            "source": "otx",
            "malicious": False,
        },
        {
            "source": "abuseipdb",
            "malicious": False,
        },
        {
            "source": "threatfox",
            "malicious": False,
        },
    ]

    print()
    print("Storing analysis...")

    result = store_analysis_result(
        indicator=indicator,
        indicator_type="ipv4",
        risk_result=risk_result,
        intelligence_results=intelligence_results,
    )

    print()
    print("Stored:")
    print(result)

    print()
    print("Retrieving latest analysis...")

    latest = get_latest_analysis(
        indicator
    )

    print()
    print("Latest analysis:")

    print(latest)

    print()
    print("=" * 60)
    print("ANALYSIS STORAGE TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()

