import os
import httpx


ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


async def lookup_abuseipdb(indicator: str):
    """
    Query AbuseIPDB for an IP address.
    """

    if not ABUSEIPDB_API_KEY:
        return {
            "source": "AbuseIPDB",
            "status": "not_configured",
            "data": None,
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": indicator,
        "maxAgeInDays": 90,
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                headers=headers,
                params=params,
            )

        if response.status_code != 200:
            return {
                "source": "AbuseIPDB",
                "status": "error",
                "status_code": response.status_code,
                "data": None,
            }

        return {
            "source": "AbuseIPDB",
            "status": "success",
            "data": response.json(),
        }

    except Exception as exc:
        return {
            "source": "AbuseIPDB",
            "status": "error",
            "error": str(exc),
            "data": None,
        }
