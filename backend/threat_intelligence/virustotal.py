import os
import httpx


VT_API_KEY = os.getenv("VT_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def lookup_virustotal(
    indicator: str,
    indicator_type: str,
):
    """
    Query VirusTotal for an IOC.
    """

    if not VT_API_KEY:
        return {
            "source": "VirusTotal",
            "status": "not_configured",
            "data": None,
        }

    type_mapping = {
        "IP": "ip_addresses",
        "DOMAIN": "domains",
        "URL": "urls",
        "HASH": "files",
    }

    vt_type = type_mapping.get(indicator_type.upper())

    if not vt_type:
        return {
            "source": "VirusTotal",
            "status": "unsupported_type",
            "data": None,
        }

    url = f"{VT_BASE_URL}/{vt_type}/{indicator}"

    headers = {
        "x-apikey": VT_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                url,
                headers=headers,
            )

        if response.status_code != 200:
            return {
                "source": "VirusTotal",
                "status": "error",
                "status_code": response.status_code,
                "data": None,
            }

        return {
            "source": "VirusTotal",
            "status": "success",
            "data": response.json(),
        }

    except Exception as exc:
        return {
            "source": "VirusTotal",
            "status": "error",
            "error": str(exc),
            "data": None,
        }
