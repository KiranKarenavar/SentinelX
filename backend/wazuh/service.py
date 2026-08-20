from .parser import (
    extract_iocs_from_alert,
)

from threat_intelligence.aggregator import (
    aggregate_intelligence,
)


async def process_wazuh_alert(
    alert: dict,
) -> list[dict]:
    """
    Process one Wazuh alert.

    Extract IOCs and send them to
    the SentinelX intelligence engine.
    """

    iocs = extract_iocs_from_alert(
        alert
    )

    results = []

    for ioc in iocs:

        intelligence = (
            await aggregate_intelligence(
                indicator=ioc["indicator"],
                indicator_type=ioc["type"],
            )
        )

        results.append(
            {
                "wazuh_source": ioc,
                "intelligence": intelligence,
            }
        )

    return results
