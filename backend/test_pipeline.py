import asyncio

from app.threat_intelligence.aggregator import (
    aggregate_ip_intelligence,
)

from app.threat_intelligence.storage import (
    store_aggregated_results,
)


async def main():

    ip_address = "8.8.8.8"

    print("=" * 60)
    print("SENTINELX THREAT INTELLIGENCE PIPELINE")
    print("=" * 60)

    print()
    print(f"IOC: {ip_address}")

    print()
    print("Step 1: Querying threat intelligence...")

    result = await aggregate_ip_intelligence(ip_address)

    print("Sources contacted:")
    print(result["sources"])

    print()
    print("Step 2: Storing results in PostgreSQL...")

    stored = store_aggregated_results(
        result["results"]
    )

    print()
    print("Stored records:")

    for item in stored:
        print(item)

    print()
    print("=" * 60)
    print("PIPELINE COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
