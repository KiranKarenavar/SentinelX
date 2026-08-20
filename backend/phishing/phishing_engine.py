from typing import Any

from phishing.email_parser import EmailParser
from phishing.header_analyzer import HeaderAnalyzer
from phishing.url_extractor import URLExtractor
from phishing.attachment_analyzer import (
    AttachmentAnalyzer,
)


class PhishingEngine:

    MITRE_TECHNIQUE = "T1566.002"

    def __init__(self):

        self.email_parser = EmailParser()
        self.header_analyzer = HeaderAnalyzer()
        self.url_extractor = URLExtractor()
        self.attachment_analyzer = (
            AttachmentAnalyzer()
        )

    async def analyze(
        self,
        file_bytes: bytes,
        filename: str,
    ) -> dict[str, Any]:

        parsed = self.email_parser.parse(
            file_bytes
        )

        headers = parsed["headers"]

        body_text = "\n".join(
            item["content"]
            for item in parsed["body_parts"]
        )

        header_analysis = (
            self.header_analyzer.analyze(
                headers
            )
        )

        iocs = self.url_extractor.extract(
            body_text
        )

        attachment_analysis = (
            self.attachment_analyzer.analyze(
                parsed["attachments"]
            )
        )

        score = 0
        indicators = []

        # Header score
        score += header_analysis["score"]

        indicators.extend(
            header_analysis["indicators"]
        )

        # URL score
        if iocs["urls"]:

            score += 15

            indicators.append(
                "Suspicious URL present"
            )

        # Domain score
        if iocs["domains"]:

            score += 10

            indicators.append(
                "Domain extracted from email"
            )

        # IP score
        if iocs["ips"]:

            score += 10

            indicators.append(
                "IP address found in email"
            )

        # Attachment score
        score += attachment_analysis["score"]

        indicators.extend(
            attachment_analysis["indicators"]
        )

        score = min(score, 100)

        verdict = self._verdict(score)

        return {
            "filename": filename,

            "sender": headers.get(
                "From"
            ),

            "recipient": headers.get(
                "To"
            ),

            "subject": headers.get(
                "Subject"
            ),

            "iocs": iocs,

            "authentication": (
                header_analysis
            ),

            "attachments": (
                attachment_analysis
            ),

            "phishing_score": score,

            "verdict": verdict,

            "indicators": indicators,

            "mitre": {
                "technique": self.MITRE_TECHNIQUE,
                "name": (
                    "Phishing: Spearphishing Link"
                ),
            },
        }

    @staticmethod
    def _verdict(score: int) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        if score >= 20:
            return "LOW"

        return "INFORMATIONAL"
