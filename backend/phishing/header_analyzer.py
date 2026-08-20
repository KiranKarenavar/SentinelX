from typing import Any


class HeaderAnalyzer:
    """
    Analyze email authentication headers.
    """

    def analyze(
        self,
        headers: dict[str, str],
    ) -> dict[str, Any]:

        received_spf = headers.get(
            "Received-SPF",
            "",
        )

        authentication_results = headers.get(
            "Authentication-Results",
            "",
        )

        spf = self._check_result(
            received_spf,
            "spf",
        )

        dkim = self._check_result(
            authentication_results,
            "dkim",
        )

        dmarc = self._check_result(
            authentication_results,
            "dmarc",
        )

        score = 0
        indicators = []

        if spf == "fail":
            score += 20
            indicators.append("SPF failure")

        if dkim == "fail":
            score += 20
            indicators.append("DKIM failure")

        if dmarc == "fail":
            score += 20
            indicators.append("DMARC failure")

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "score": score,
            "indicators": indicators,
        }

    @staticmethod
    def _check_result(
        value: str,
        protocol: str,
    ) -> str:

        value = value.lower()

        if f"{protocol}=pass" in value:
            return "pass"

        if f"{protocol}=fail" in value:
            return "fail"

        if f"{protocol}=softfail" in value:
            return "softfail"

        if f"{protocol}=neutral" in value:
            return "neutral"

        return "unknown"
