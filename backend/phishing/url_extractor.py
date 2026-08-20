import re
from urllib.parse import urlparse
from typing import Any


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4][0-9]|"
    r"1[0-9]{2}|[1-9]?[0-9])\."
    r"){3}"
    r"(?:25[0-5]|2[0-4][0-9]|"
    r"1[0-9]{2}|[1-9]?[0-9])\b"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


class URLExtractor:

    def extract(
        self,
        text: str,
    ) -> dict[str, Any]:

        urls = set(URL_PATTERN.findall(text))

        domains = set()
        ips = set()

        for url in urls:

            try:

                parsed = urlparse(url)

                hostname = parsed.hostname

                if hostname:

                    domains.add(
                        hostname.lower()
                    )

            except Exception:
                continue

        ips.update(
            IP_PATTERN.findall(text)
        )

        md5 = set(
            MD5_PATTERN.findall(text)
        )

        sha1 = set(
            SHA1_PATTERN.findall(text)
        )

        sha256 = set(
            SHA256_PATTERN.findall(text)
        )

        return {
            "urls": sorted(urls),
            "domains": sorted(domains),
            "ips": sorted(ips),
            "hashes": {
                "md5": sorted(md5),
                "sha1": sorted(sha1),
                "sha256": sorted(sha256),
            },
        }
