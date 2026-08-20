from typing import Any, Dict

from app.phishing.parser import parse_email
from app.phishing.ioc_extractor import extract_iocs
from app.phishing.analyzer import analyze_email

from app.threat_intelligence.aggregator import (
    aggregate_ip_intelligence,
)


class PhishingEngine:

    async def investigate(
        self,
        raw_email: bytes,
    ) -> Dict[str, Any]:

        # =========================================
        # STEP 1 — Parse email
        # =========================================

        parsed = parse_email(
            raw_email
        )

        headers = parsed.get(
            "headers",
            {}
        )

        body = parsed.get(
            "body",
            ""
        )

        # =========================================
        # STEP 2 — Combine email content
        # =========================================

        header_text = "\n".join(
            f"{key}: {value}"
            for key, value in headers.items()
            if value
        )

        combined_text = (
            header_text
            + "\n"
            + body
        )

        # =========================================
        # STEP 3 — Extract IOCs
        # =========================================

        iocs = extract_iocs(
            combined_text
        )

        # =========================================
        # STEP 4 — Local phishing analysis
        # =========================================

        analysis = analyze_email(
            parsed,
            iocs,
        )

        # =========================================
        # STEP 5 — Threat Intelligence
        # =========================================

        threat_intelligence = []

        for ip in iocs.get("ips", []):

            try:

                result = await aggregate_ip_intelligence(
                    ip
                )

                threat_intelligence.append({
                    "ioc": ip,
                    "type": "ipv4",
                    "result": result,
                })

            except Exception as exc:

                threat_intelligence.append({
                    "ioc": ip,
                    "type": "ipv4",
                    "error": str(exc),
                })

        # =========================================
        # STEP 6 — Return investigation
        # =========================================

        return {

            "email": {
                "headers": headers,
            },

            "iocs": iocs,

            "analysis": analysis,

            "threat_intelligence": (
                threat_intelligence
            ),
        }
