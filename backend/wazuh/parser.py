import ipaddress
import re


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def is_valid_ip(value: str) -> bool:
    """
    Check whether a string is a valid IPv4/IPv6 address.
    """

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def extract_ips_from_text(
    text: str,
) -> list[str]:
    """
    Extract valid IPv4 addresses from text.
    """

    if not text:
        return []

    matches = IP_PATTERN.findall(text)

    valid_ips = []

    for ip in matches:

        if is_valid_ip(ip):
            valid_ips.append(ip)

    return list(
        dict.fromkeys(valid_ips)
    )


def extract_iocs_from_alert(
    alert: dict,
) -> list[dict]:
    """
    Extract IOC candidates from a Wazuh alert.
    """

    iocs = []

    data = alert.get(
        "data",
        {},
    )

    # --------------------------------
    # Source IP
    # --------------------------------

    srcip = data.get("srcip")

    if srcip and is_valid_ip(srcip):

        iocs.append(
            {
                "indicator": srcip,
                "type": "ip",
                "source": "Wazuh",
            }
        )

    # --------------------------------
    # Destination IP
    # --------------------------------

    dstip = data.get("dstip")

    if dstip and is_valid_ip(dstip):

        iocs.append(
            {
                "indicator": dstip,
                "type": "ip",
                "source": "Wazuh",
            }
        )

    # --------------------------------
    # Alert description
    # --------------------------------

    description = (
        alert.get("rule", {})
        .get("description", "")
    )

    for ip in extract_ips_from_text(
        description
    ):

        iocs.append(
            {
                "indicator": ip,
                "type": "ip",
                "source": "Wazuh",
            }
        )

    # --------------------------------
    # Remove duplicates
    # --------------------------------

    unique = {}

    for ioc in iocs:

        key = (
            ioc["indicator"],
            ioc["type"],
        )

        unique[key] = ioc

    return list(
        unique.values()
    )

