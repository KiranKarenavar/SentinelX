import asyncio

from app.threat_intelligence.abuseipdb import check_ip_reputation


async def main():
    ip = "8.8.8.8"

    try:
        result = await check_ip_reputation(ip)

        data = result.get("data", {})

        print("AbuseIPDB connection successful")
        print("IP Address:", data.get("ipAddress"))
        print("Abuse Confidence Score:", data.get("abuseConfidenceScore"))
        print("Country:", data.get("countryCode"))
        print("ISP:", data.get("isp"))
        print("Total Reports:", data.get("totalReports"))

    except Exception as error:
        print("AbuseIPDB connection failed")
        print("Error:", error)


if __name__ == "__main__":
    asyncio.run(main())
