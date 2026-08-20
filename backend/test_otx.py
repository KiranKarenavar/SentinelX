import asyncio

from app.threat_intelligence.otx import get_ip_reputation


async def main():
    ip = "8.8.8.8"

    try:
        result = await get_ip_reputation(ip)

        print("OTX connection successful")
        print("Indicator:", result.get("indicator"))
        print("Type:", result.get("type"))

    except Exception as error:
        print("OTX connection failed")
        print("Error:", error)


if __name__ == "__main__":
    asyncio.run(main())
