import os
import httpx


OTX_API_KEY = os.getenv("OTX_API_KEY")

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


async def lookup_otx(indicator: str, indicator_type: str):
    """
    Query AlienVault OTX for an IOC.
    """

    if not OTX_API_KEY:
        return {
            "source": "OTX",
            "status": "not_configured",
            "data": None,
        }

    type_mapping = {
        "IP": "IPv4",
        "DOMAIN": "domain",
        "URL": "url",
        "HASH": "file",
    }

    otx_type = type_mapping.get(indicator_type.upper())

    if not otx_type:
        return {
            "source": "OTX",
            "status": "unsupported_type",
            "data": None,
        }

    url = f"{OTX_BASE_URL}/indicators/{otx_type}/{indicator}/general"

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                url,
                headers=headers,
            )

        if response.status_code != 200:
            return {
                "source": "OTX",
                "status": "error",
                "status_code": response.status_code,
                "data": None,
            }

        return {
            "source": "OTX",
            "status": "success",
            "data": response.json(),
        }

    except Exception as exc:
        return {
            "source": "OTX",
            "status": "error",
            "error": str(exc),
            "data": None,
        }
