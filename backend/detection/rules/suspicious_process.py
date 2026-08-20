from typing import Any


SUSPICIOUS_PROCESSES = {
    "mimikatz.exe",
    "powershell_encoded",
    "psexec.exe",
    "nc.exe",
    "netcat",
    "rundll32.exe",
    "regsvr32.exe",
}


def detect_suspicious_process(
    event: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Detect potentially suspicious process execution.
    """

    process = str(
        event.get("process", "")
    ).lower()

    command = str(
        event.get("command", "")
    ).lower()

    detections = []

    for suspicious in SUSPICIOUS_PROCESSES:

        if (
            suspicious in process
            or suspicious in command
        ):

            detections.append(
                {
                    "detection_type": (
                        "SUSPICIOUS_PROCESS"
                    ),
                    "process": process,
                    "command": command,
                    "severity": "HIGH",
                    "description": (
                        f"Suspicious process detected: "
                        f"{suspicious}"
                    ),
                }
            )

            break

    return detections
