import httpx

from app.config import ABUSEIPDB_API_KEY


ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"


async def check_ip_reputation(ip_address: str):
    """
    Query AbuseIPDB for reputation information about an IP address.
    """

    if not ABUSEIPDB_API_KEY:
        raise RuntimeError("ABUSEIPDB_API_KEY is not configured")

    url = f"{ABUSEIPDB_BASE_URL}/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(
            url,
            headers=headers,
            params=params,
        )

    response.raise_for_status()

    return response.json()
