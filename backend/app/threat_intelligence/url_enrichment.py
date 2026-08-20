from typing import Any, Dict, List
from urllib.parse import urlparse


def enrich_url(
    url: str,
    intelligence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Extract URL-related enrichment from
    normalized threat-intelligence results.
    """

    parsed = urlparse(url)

    result = {
        "url": url,
        "scheme": parsed.scheme,
        "domain": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "malicious": False,
        "confidence": 0,
        "sources": [],
        "threatfox_result": "no_result",
        "otx_pulse_count": 0,
        "malware_families": [],
        "threat_actors": [],
        "tags": [],
        "references": [],
    }

    confidence_values = []

    for item in intelligence:

        source = item.get("source")

        # -----------------------------------------
        # Sources
        # -----------------------------------------

        if source and source not in result["sources"]:

            result["sources"].append(source)

        # -----------------------------------------
        # Malicious
        # -----------------------------------------

        if item.get("malicious") is True:

            result["malicious"] = True

        # -----------------------------------------
        # Confidence
        # -----------------------------------------

        confidence = item.get("confidence")

        if confidence is not None:

            try:
                confidence_values.append(
                    int(confidence)
                )

            except (TypeError, ValueError):
                pass

        raw_data = item.get(
            "raw_data",
            {}
        )

        if not isinstance(raw_data, dict):
            continue

        # =========================================
        # OTX
        # =========================================

        if source == "otx":

            pulse_info = raw_data.get(
                "pulse_info",
                {}
            )

            if isinstance(
                pulse_info,
                dict
            ):

                pulses = pulse_info.get(
                    "pulses",
                    []
                )

                if isinstance(
                    pulses,
                    list
                ):

                    result[
                        "otx_pulse_count"
                    ] = len(pulses)

                    for pulse in pulses:

                        if not isinstance(
                            pulse,
                            dict
                        ):
                            continue

                        tags = pulse.get(
                            "tags",
                            []
                        )

                        if isinstance(
                            tags,
                            list
                        ):

                            result[
                                "tags"
                            ].extend(
                                str(tag)
                                for tag in tags
                            )

                        references = pulse.get(
                            "references",
                            []
                        )

                        if isinstance(
                            references,
                            list
                        ):

                            result[
                                "references"
                            ].extend(
                                str(ref)
                                for ref in references
                            )

                        malware = pulse.get(
                            "malware_families",
                            []
                        )

                        if isinstance(
                            malware,
                            list
                        ):

                            result[
                                "malware_families"
                            ].extend(
                                str(item)
                                for item in malware
                            )

        # =========================================
        # ThreatFox
        # =========================================

        if source == "threatfox":

            query_status = raw_data.get(
                "query_status"
            )

            if query_status:

                result[
                    "threatfox_result"
                ] = query_status

            data = raw_data.get(
                "data"
            )

            if isinstance(
                data,
                list
            ):

                result[
                    "threatfox_result"
                ] = "match"

                for entry in data:

                    if not isinstance(
                        entry,
                        dict
                    ):
                        continue

                    malware = entry.get(
                        "malware_printable"
                    )

                    if malware:

                        result[
                            "malware_families"
                        ].append(
                            malware
                        )

                    threat_actor = entry.get(
                        "threat_actor"
                    )

                    if threat_actor:

                        result[
                            "threat_actors"
                        ].append(
                            threat_actor
                        )

                    tags = entry.get(
                        "tags",
                        []
                    )

                    if isinstance(
                        tags,
                        list
                    ):

                        result[
                            "tags"
                        ].extend(
                            str(tag)
                            for tag in tags
                        )

    # =========================================
    # Average confidence
    # =========================================

    if confidence_values:

        result[
            "confidence"
        ] = round(
            sum(confidence_values)
            / len(confidence_values)
        )

    # =========================================
    # Remove duplicates
    # =========================================

    result["sources"] = sorted(
        set(result["sources"])
    )

    result["malware_families"] = sorted(
        set(result["malware_families"])
    )

    result["threat_actors"] = sorted(
        set(result["threat_actors"])
    )

    result["tags"] = sorted(
        set(result["tags"])
    )

    result["references"] = sorted(
        set(result["references"])
    )

    return result
