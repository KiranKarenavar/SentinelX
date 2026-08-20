import asyncio

from app.threat_intelligence.enrichment_router import (
    enrich_ioc,
)


TEST_IOCS = [
    "8.8.8.8",
    "google.com",
    "https://google.com",
    "d41d8cd98f00b204e9800998ecf8427e",
]


async def test_ioc(ioc: str):

    print("=" * 60)
    print(f"Testing IOC: {ioc}")
    print("=" * 60)

    try:

        result = await enrich_ioc(ioc)

        print("IOC Type:")
        print(result.get("ioc_type"))

        print()

        print("Status:")
        print(result.get("status"))

        print()

        print("Enrichment:")

        enrichment = result.get(
            "enrichment"
        )

        if enrichment is not None:
            print(enrichment)

        else:
            print(
                result.get("error")
            )

        print()

    except Exception as error:

        print("ERROR:")
        print(error)

    print()


async def main():

    print()
    print("=" * 60)
    print("SENTINELX UNIVERSAL IOC ENRICHMENT TEST")
    print("=" * 60)
    print()

    for ioc in TEST_IOCS:

        await test_ioc(ioc)

    print("=" * 60)
    print("UNIVERSAL ENRICHMENT TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":

    asyncio.run(main())
