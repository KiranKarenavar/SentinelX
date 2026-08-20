import httpx


THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def lookup_threatfox(indicator: str):
    """
    Query ThreatFox for an IOC.
    """

    payload = {
        "query": "search_ioc",
        "search_term": indicator,
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                THREATFOX_URL,
                json=payload,
            )

        if response.status_code != 200:
            return {
                "source": "ThreatFox",
                "status": "error",
                "status_code": response.status_code,
                "data": None,
            }

        return {
            "source": "ThreatFox",
            "status": "success",
            "data": response.json(),
        }

    except Exception as exc:
        return {
            "source": "ThreatFox",
            "status": "error",
            "error": str(exc),
            "data": None,
        }
