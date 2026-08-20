from typing import Any, Dict, List

from app.threat_intelligence.ioc_detector import (
    detect_ioc_type,
)

from app.threat_intelligence.aggregator import (
    aggregate_ip_intelligence,
)

from app.threat_intelligence.risk_engine import (
    calculate_verdict,
)

from app.honeypot.storage import (
    store_honeypot_event,
)

from app.ml.integration import (
    MLEventAnalyzer,
)


class HoneypotEngine:

    def __init__(self):

        self.ml = MLEventAnalyzer()

    def extract_iocs(
        self,
        event: Dict[str, Any],
    ) -> List[str]:

        iocs = []

        for field in [
            "source_ip",
            "destination_ip",
        ]:

            value = event.get(field)

            if not value:
                continue

            if (
                detect_ioc_type(value)
                == "ipv4"
            ):

                if value not in iocs:
                    iocs.append(value)

        return iocs

    async def investigate(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        iocs = self.extract_iocs(
            event
        )

        threat_intelligence = []

        for ioc in iocs:

            try:

                result = (
                    await aggregate_ip_intelligence(
                        ioc
                    )
                )

                threat_intelligence.append(
                    {
                        "ioc": ioc,
                        "result": result,
                    }
                )

            except Exception as exc:

                threat_intelligence.append(
                    {
                        "ioc": ioc,
                        "error": str(exc),
                    }
                )

        intelligence_results = []

        for item in threat_intelligence:

            result = item.get(
                "result",
                {},
            )

            if not isinstance(
                result,
                dict,
            ):
                continue

            results = result.get(
                "results",
                [],
            )

            if isinstance(
                results,
                list,
            ):

                intelligence_results.extend(
                    results
                )

        if intelligence_results:

            risk_result = calculate_verdict(
                intelligence_results
            )

        else:

            risk_result = {
                "score": 0,
                "severity": "INFO",
                "verdict": "UNKNOWN",
                "reasons": [],
                "provider_scores": [],
            }

        ml_result = self.ml.analyze(
            event
        )

        storage = store_honeypot_event(
            event
        )

        return {
            "status": "success",

            "event": event,

            "iocs": iocs,

            "threat_intelligence":
                threat_intelligence,

            "analysis": {
                "score": int(
                    risk_result.get(
                        "risk_score",
                        risk_result.get(
                            "score",
                            0,
                        ),
                    )
                ),
                "severity": risk_result.get(
                    "severity",
                    "INFO",
                ),
                "verdict": risk_result.get(
                    "verdict",
                    "UNKNOWN",
                ),
                "reasons": risk_result.get(
                    "reasons",
                    [],
                ),
            },

            "machine_learning": ml_result,

            "storage": storage,
        }
