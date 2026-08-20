import re
import ipaddress
import tldextract
from typing import Dict, List


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def extract_urls(text: str) -> List[str]:

    return list(
        dict.fromkeys(
            URL_PATTERN.findall(text or "")
        )
    )


def extract_ips(text: str) -> List[str]:

    results = []

    for value in IP_PATTERN.findall(text or ""):

        try:
            ipaddress.ip_address(value)
            results.append(value)

        except ValueError:
            pass

    return list(dict.fromkeys(results))


def extract_domains(text: str) -> List[str]:

    domains = []

    for url in extract_urls(text):

        extracted = tldextract.extract(url)

        if extracted.domain and extracted.suffix:

            domains.append(
                f"{extracted.domain}.{extracted.suffix}"
            )

    return list(
        dict.fromkeys(domains)
    )


def extract_iocs(text: str) -> Dict[str, List[str]]:

    return {
        "urls": extract_urls(text),
        "ips": extract_ips(text),
        "domains": extract_domains(text),
    }
