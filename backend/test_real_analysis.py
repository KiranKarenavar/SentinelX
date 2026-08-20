import asyncio

from app.threat_intelligence.aggregator import (
    aggregate_ip_intelligence,
)

from app.threat_intelligence.analyzer import (
    analyze_ip,
)


IOC = "8.8.8.8"


async def main():

    print("=" * 60)
    print("SENTINELX REAL IOC ANALYSIS")
    print("=" * 60)

    print()

    print("IOC:")
    print(IOC)

    print()

    # -----------------------------------------
    # STEP 1 — Query threat intelligence
    # -----------------------------------------

    print(
        "STEP 1: Querying threat intelligence..."
    )

    result = await aggregate_ip_intelligence(
        IOC
    )

    intelligence = result.get(
        "results",
        []
    )

    print()

    print("Sources contacted:")

    for source in result.get(
        "sources",
        []
    ):
        print("-", source)

    print()

    # -----------------------------------------
    # STEP 2 — Enrichment + Risk Analysis
    # -----------------------------------------

    print(
        "STEP 2: Enrichment + Risk Analysis..."
    )

    analysis = analyze_ip(
        intelligence
    )

    print()

    # -----------------------------------------
    # STEP 3 — Enrichment
    # -----------------------------------------

    print("=" * 60)
    print("ENRICHMENT")
    print("=" * 60)

    for key, value in analysis[
        "enrichment"
    ].items():

        print(
            f"{key}: {value}"
        )

    print()

    # -----------------------------------------
    # STEP 4 — Risk
    # -----------------------------------------

    print("=" * 60)
    print("RISK ANALYSIS")
    print("=" * 60)

    risk = analysis[
        "risk"
    ]

    print()

    print(
        "Risk Score:",
        risk["score"]
    )

    print(
        "Severity:",
        risk["severity"]
    )

    print(
        "Verdict:",
        risk["verdict"]
    )

    print()

    print("Reasons:")

    if risk["reasons"]:

        for reason in risk["reasons"]:
            print(
                "-",
                reason
            )

    else:

        print(
            "- No significant risk indicators"
        )

    print()

    # -----------------------------------------
    # STEP 5 — Provider scores
    # -----------------------------------------

    print("=" * 60)
    print("PROVIDER SCORES")
    print("=" * 60)

    for provider in risk[
        "provider_scores"
    ]:

        print(provider)

    print()

    print("=" * 60)
    print("ANALYSIS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":

    asyncio.run(
        main()
    )
