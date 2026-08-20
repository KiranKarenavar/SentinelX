from typing import Any, Dict, List


def enrich_hash(
    file_hash: str,
    hash_type: str,
    intelligence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Extract file-hash related threat intelligence.

    Supported hash types:

        md5
        sha1
        sha256
    """

    result = {
        "hash": file_hash,
        "hash_type": hash_type,
        "malicious": False,
        "confidence": 0,
        "sources": [],
        "malware_families": [],
        "threat_actors": [],
        "tags": [],
        "references": [],
        "first_seen": None,
        "last_seen": None,
    }

    confidence_values = []

    for item in intelligence:

        source = item.get(
            "source"
        )

        # =========================================
        # Sources
        # =========================================

        if source and source not in result["sources"]:

            result["sources"].append(
                source
            )

        # =========================================
        # Malicious verdict
        # =========================================

        if item.get("malicious") is True:

            result["malicious"] = True

        # =========================================
        # Confidence
        # =========================================

        confidence = item.get(
            "confidence"
        )

        if confidence is not None:

            try:

                confidence_values.append(
                    int(confidence)
                )

            except (
                TypeError,
                ValueError,
            ):
                pass

        # =========================================
        # Standard fields
        # =========================================

        first_seen = item.get(
            "first_seen"
        )

        if first_seen and not result[
            "first_seen"
        ]:

            result[
                "first_seen"
            ] = first_seen

        last_seen = item.get(
            "last_seen"
        )

        if last_seen:

            result[
                "last_seen"
            ] = last_seen

        # =========================================
        # Raw provider data
        # =========================================

        raw_data = item.get(
            "raw_data",
            {}
        )

        if not isinstance(
            raw_data,
            dict
        ):
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

                    for pulse in pulses:

                        if not isinstance(
                            pulse,
                            dict
                        ):
                            continue

                        # Tags

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

                        # References

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

                        # Malware families

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
                                str(name)
                                for name in malware
                            )

        # =========================================
        # ThreatFox
        # =========================================

        if source == "threatfox":

            query_status = raw_data.get(
                "query_status"
            )

            if query_status == "ok":

                data = raw_data.get(
                    "data"
                )

                if isinstance(
                    data,
                    list
                ):

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
    # Calculate average confidence
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

    result[
        "sources"
    ] = sorted(
        set(
            result["sources"]
        )
    )

    result[
        "malware_families"
    ] = sorted(
        set(
            result["malware_families"]
        )
    )

    result[
        "threat_actors"
    ] = sorted(
        set(
            result["threat_actors"]
        )
    )

    result[
        "tags"
    ] = sorted(
        set(
            result["tags"]
        )
    )

    result[
        "references"
    ] = sorted(
        set(
            result["references"]
        )
    )

    return result
