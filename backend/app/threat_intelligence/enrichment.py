from typing import Any, Dict, List


def enrich_ip(intelligence: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract useful IP enrichment information from
    OTX, AbuseIPDB and ThreatFox results.
    """

    enrichment = {
        "country": None,
        "isp": None,
        "asn": None,
        "domain": None,
        "hostnames": [],
        "is_tor": False,
        "is_whitelisted": False,
        "total_reports": 0,
        "abuse_confidence": 0,
        "otx_reputation": 0,
        "otx_pulse_count": 0,
        "threatfox_result": None,
        "malware_families": [],
        "tags": [],
    }

    for item in intelligence:

        source = item.get("source")

        raw_data = item.get("raw_data", {})

        if not isinstance(raw_data, dict):
            continue

        # =====================================
        # OTX
        # =====================================

        if source == "otx":

            enrichment["otx_reputation"] = raw_data.get(
                "reputation",
                0
            )

            pulse_info = raw_data.get(
                "pulse_info",
                {}
            )

            if isinstance(pulse_info, dict):

                pulses = pulse_info.get(
                    "pulses",
                    []
                )

                if isinstance(pulses, list):

                    enrichment["otx_pulse_count"] = len(
                        pulses
                    )

                    for pulse in pulses:

                        if not isinstance(pulse, dict):
                            continue

                        malware_families = pulse.get(
                            "malware_families",
                            []
                        )

                        if isinstance(
                            malware_families,
                            list
                        ):
                            enrichment[
                                "malware_families"
                            ].extend(
                                malware_families
                            )

            enrichment["country"] = (
                raw_data.get("country_code2")
                or enrichment["country"]
            )

            enrichment["asn"] = raw_data.get(
                "asn"
            )

        # =====================================
        # AbuseIPDB
        # =====================================

        elif source == "abuseipdb":

            data = raw_data.get(
                "data",
                {}
            )

            if not isinstance(data, dict):
                continue

            enrichment["country"] = (
                data.get("countryCode")
                or enrichment["country"]
            )

            enrichment["isp"] = data.get(
                "isp"
            )

            enrichment["domain"] = data.get(
                "domain"
            )

            enrichment["hostnames"] = data.get(
                "hostnames",
                []
            )

            enrichment["is_tor"] = data.get(
                "isTor",
                False
            )

            enrichment["is_whitelisted"] = data.get(
                "isWhitelisted",
                False
            )

            enrichment["total_reports"] = data.get(
                "totalReports",
                0
            )

            enrichment["abuse_confidence"] = data.get(
                "abuseConfidenceScore",
                0
            )

        # =====================================
        # ThreatFox
        # =====================================

        elif source == "threatfox":

            query_status = raw_data.get(
                "query_status"
            )

            enrichment["threatfox_result"] = (
                query_status
            )

            # ThreatFox no_result is NOT malicious.
            if query_status == "no_result":
                continue

    # =========================================
    # Remove duplicate malware families
    # =========================================

    enrichment["malware_families"] = list(
        dict.fromkeys(
            enrichment["malware_families"]
        )
    )

    return enrichment
