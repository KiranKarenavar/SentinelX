import asyncio
import time

from app.threat_intelligence.aggregator import (
    aggregate_ip_intelligence,
)


async def main():

    ip_address = "8.8.8.8"

    print(f"Querying threat intelligence for: {ip_address}")
    print()

    start_time = time.perf_counter()

    result = await aggregate_ip_intelligence(ip_address)

    end_time = time.perf_counter()

    elapsed = end_time - start_time

    print("Sources contacted:")
    print(result["sources"])

    print()
    print(f"Total time: {elapsed:.2f} seconds")

    print()
    print("Results:")

    for item in result["results"]:
        print(item)

    print()
    print("Deduplicated:")

    for item in result["deduplicated"]:
        print(item)


if __name__ == "__main__":
    asyncio.run(main())
