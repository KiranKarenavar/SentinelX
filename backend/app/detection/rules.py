DETECTION_RULES = [

    {
        "rule_id": "SX-001",
        "name": "PowerShell Execution",
        "description": "Detects PowerShell process execution",
        "severity": "MEDIUM",
        "event_type": "process_creation",
        "conditions": {
            "process_names": [
                "powershell.exe",
                "pwsh.exe"
            ]
        }
    },

    {
        "rule_id": "SX-002",
        "name": "Command Shell Execution",
        "description": "Detects Windows command shell execution",
        "severity": "LOW",
        "event_type": "process_creation",
        "conditions": {
            "process_names": [
                "cmd.exe"
            ]
        }
    },

    {
        "rule_id": "SX-003",
        "name": "Suspicious Network Connection",
        "description": "Detects suspicious outbound network activity",
        "severity": "HIGH",
        "event_type": "network_connection",
        "conditions": {
            "suspicious": True
        }
    },

    {
        "rule_id": "SX-004",
        "name": "Encoded PowerShell",
        "description": "Detects encoded PowerShell execution",
        "severity": "HIGH",
        "event_type": "process_creation",
        "conditions": {
            "keywords": [
                "-enc",
                "-encodedcommand"
            ]
        }
    },

    {
        "rule_id": "SX-005",
        "name": "PowerShell Download Activity",
        "description": "Detects PowerShell download-related commands",
        "severity": "HIGH",
        "event_type": "process_creation",
        "conditions": {
            "keywords": [
                "invoke-webrequest",
                "downloadstring",
                "downloadfile",
                "webclient"
            ]
        }
    },

    {
        "rule_id": "SX-006",
        "name": "Suspicious DNS Query",
        "description": "Detects DNS queries for suspicious domains",
        "severity": "MEDIUM",
        "event_type": "dns_query",
        "conditions": {
            "keywords": [
                ".tk",
                ".xyz",
                ".top",
                ".click"
            ]
        }
    }
]
