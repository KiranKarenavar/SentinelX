import httpx

from app.config import OTX_API_KEY


OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


async def get_ip_reputation(ip_address: str):
    """
    Query AlienVault OTX for information about an IP address.
    """

    if not OTX_API_KEY:
        raise RuntimeError("OTX_API_KEY is not configured")

    url = f"{OTX_BASE_URL}/indicators/IPv4/{ip_address}/general"

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(
            url,
            headers=headers
        )

    response.raise_for_status()

    return response.json()
