import httpx

from app.config import THREATFOX_AUTH_KEY


THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def query_threatfox(
    ioc: str,
):
    """
    Search ThreatFox for an IOC.
    """

    if not THREATFOX_AUTH_KEY:
        raise RuntimeError("THREATFOX_AUTH_KEY is not configured")

    headers = {
        "Auth-Key": THREATFOX_AUTH_KEY,
        "Content-Type": "application/json",
    }

    payload = {
        "query": "search_ioc",
        "search_term": ioc,
        "exact_match": True,
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            THREATFOX_API_URL,
            headers=headers,
            json=payload,
        )

    response.raise_for_status()

    return response.json()
