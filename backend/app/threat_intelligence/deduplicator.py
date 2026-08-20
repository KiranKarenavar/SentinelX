from typing import Any, Dict, List


def deduplicate_iocs(
    results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Merge intelligence records that belong to the same IOC.

    The IOC identity is based on:
        ioc_type + value
    """

    ioc_map: Dict[str, Dict[str, Any]] = {}

    for result in results:

        # Ignore provider errors.
        if "error" in result:
            continue

        ioc_type = result.get("ioc_type")
        value = result.get("value")

        if not ioc_type or not value:
            continue

        key = f"{ioc_type}:{value}"

        if key not in ioc_map:
            ioc_map[key] = {
                "ioc_type": ioc_type,
                "value": value,
                "sources": [],
                "intelligence": [],
            }

        source = result.get("source")

        if source and source not in ioc_map[key]["sources"]:
            ioc_map[key]["sources"].append(source)

        ioc_map[key]["intelligence"].append(result)

    return list(ioc_map.values())
