import asyncio

from app.threat_intelligence.threatfox import query_threatfox


async def main():
    ioc = "8.8.8.8"

    try:
        result = await query_threatfox(ioc)

        print("ThreatFox connection successful")
        print("Response:", result)

    except Exception as error:
        print("ThreatFox connection failed")
        print("Error:", error)


if __name__ == "__main__":
    asyncio.run(main())
