from typing import Any


class AttachmentAnalyzer:
    """
    Perform basic attachment analysis.

    This version does not execute files.
    """

    SUSPICIOUS_EXTENSIONS = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".hta",
        ".apk",
    }

    def analyze(
        self,
        attachments: list[dict[str, Any]],
    ) -> dict[str, Any]:

        suspicious = []
        indicators = []

        for attachment in attachments:

            filename = (
                attachment.get("filename")
                or ""
            )

            lower_name = filename.lower()

            for extension in self.SUSPICIOUS_EXTENSIONS:

                if lower_name.endswith(extension):

                    suspicious.append(
                        attachment
                    )

                    indicators.append(
                        f"Suspicious attachment: {filename}"
                    )

                    break

        score = min(
            len(suspicious) * 15,
            30,
        )

        return {
            "total": len(attachments),
            "suspicious": suspicious,
            "score": score,
            "indicators": indicators,
        }
