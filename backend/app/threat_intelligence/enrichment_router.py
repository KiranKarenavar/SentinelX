import ipaddress
import re
from urllib.parse import urlparse

from app.threat_intelligence.enrichment import enrich_ip
from app.threat_intelligence.domain_enrichment import enrich_domain
from app.threat_intelligence.url_enrichment import enrich_url
from app.threat_intelligence.hash_enrichment import enrich_hash


MD5_PATTERN = re.compile(
    r"^[a-fA-F0-9]{32}$"
)

SHA1_PATTERN = re.compile(
    r"^[a-fA-F0-9]{40}$"
)

SHA256_PATTERN = re.compile(
    r"^[a-fA-F0-9]{64}$"
)


def detect_ioc_type(value: str) -> str:
    """
    Detect the IOC type.

    Supported:

    ipv4
    ipv6
    domain
    url
    md5
    sha1
    sha256
    unknown
    """

    value = value.strip()

    # -----------------------------------------
    # IP address detection
    # -----------------------------------------

    try:
        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return "ipv4"

        if ip.version == 6:
            return "ipv6"

    except ValueError:
        pass

    # -----------------------------------------
    # Hash detection
    # -----------------------------------------

    if MD5_PATTERN.fullmatch(value):
        return "md5"

    if SHA1_PATTERN.fullmatch(value):
        return "sha1"

    if SHA256_PATTERN.fullmatch(value):
        return "sha256"

    # -----------------------------------------
    # URL detection
    # -----------------------------------------

    if value.startswith(
        ("http://", "https://")
    ):

        parsed = urlparse(value)

        if parsed.netloc:
            return "url"

    # -----------------------------------------
    # Domain detection
    # -----------------------------------------

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if domain_pattern.fullmatch(value):
        return "domain"

    return "unknown"


async def enrich_ioc(value: str) -> dict:
    """
    Universal IOC enrichment router.

    Detects the IOC type and calls
    the appropriate enrichment module.
    """

    value = value.strip()

    if not value:
        return {
            "ioc": value,
            "ioc_type": "unknown",
            "status": "error",
            "error": "IOC value cannot be empty",
        }

    ioc_type = detect_ioc_type(value)

    # -----------------------------------------
    # IPv4
    # -----------------------------------------

    if ioc_type == "ipv4":

        result = await enrich_ip(value)

        return {
            "ioc": value,
            "ioc_type": "ipv4",
            "status": "success",
            "enrichment": result,
        }

    # -----------------------------------------
    # IPv6
    # -----------------------------------------

    if ioc_type == "ipv6":

        result = await enrich_ip(value)

        return {
            "ioc": value,
            "ioc_type": "ipv6",
            "status": "success",
            "enrichment": result,
        }

    # -----------------------------------------
    # Domain
    # -----------------------------------------

    if ioc_type == "domain":

        result = await enrich_domain(value)

        return {
            "ioc": value,
            "ioc_type": "domain",
            "status": "success",
            "enrichment": result,
        }

    # -----------------------------------------
    # URL
    # -----------------------------------------

    if ioc_type == "url":

        result = await enrich_url(value)

        return {
            "ioc": value,
            "ioc_type": "url",
            "status": "success",
            "enrichment": result,
        }

    # -----------------------------------------
    # MD5
    # -----------------------------------------

    if ioc_type == "md5":

        result = await enrich_hash(
            value,
            hash_type="md5",
        )

        return {
            "ioc": value,
            "ioc_type": "md5",
            "status": "success",
            "enrichment": result,
        }

    # -----------------------------------------
    # SHA1
    # -----------------------------------------

    if ioc_type == "sha1":

        result = await enrich_hash(
            value,
            hash_type="sha1",
        )

        return {
            "ioc": value,
            "ioc_type": "sha1",
            "status": "success",
            "enrichment": result,
        }

    # -----------------------------------------
    # SHA256
    # -----------------------------------------

    if ioc_type == "sha256":

        result = await enrich_hash(
            value,
            hash_type="sha256",
        )

        return {
            "ioc": value,
            "ioc_type": "sha256",
            "status": "success",
            "enrichment": result,
        }

    # -----------------------------------------
    # Unknown IOC
    # -----------------------------------------

    return {
        "ioc": value,
        "ioc_type": "unknown",
        "status": "error",
        "error": "Unable to determine IOC type",
    }
