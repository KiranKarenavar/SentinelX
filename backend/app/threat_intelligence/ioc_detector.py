import ipaddress
import re
from urllib.parse import urlparse


def detect_ioc_type(value: str) -> str:
    """
    Detect the type of an IOC.

    Supported types:

        ipv4
        ipv6
        domain
        url
        md5
        sha1
        sha256
        unknown
    """

    if not isinstance(value, str):
        return "unknown"

    value = value.strip()

    if not value:
        return "unknown"

    # =========================================
    # IPv4 / IPv6
    # =========================================

    try:

        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return "ipv4"

        if ip.version == 6:
            return "ipv6"

    except ValueError:
        pass

    # =========================================
    # URL
    # =========================================

    try:

        parsed = urlparse(value)

        if parsed.scheme in (
            "http",
            "https",
            "ftp",
        ) and parsed.netloc:

            return "url"

    except Exception:
        pass

    # =========================================
    # MD5
    # =========================================

    if re.fullmatch(
        r"[a-fA-F0-9]{32}",
        value,
    ):
        return "md5"

    # =========================================
    # SHA1
    # =========================================

    if re.fullmatch(
        r"[a-fA-F0-9]{40}",
        value,
    ):
        return "sha1"

    # =========================================
    # SHA256
    # =========================================

    if re.fullmatch(
        r"[a-fA-F0-9]{64}",
        value,
    ):
        return "sha256"

    # =========================================
    # Domain
    # =========================================

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
