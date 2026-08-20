HUNT_QUERIES = {

    "powershell": {
        "name": "PowerShell Activity",
        "description": "Find PowerShell executions",
        "query": {
            "match": {
                "data.win.system.eventID": "1"
            }
        }
    },

    "network": {
        "name": "Network Connections",
        "description": "Find Sysmon network connections",
        "query": {
            "match": {
                "data.win.system.eventID": "3"
            }
        }
    },

    "dns": {
        "name": "DNS Queries",
        "description": "Find Sysmon DNS queries",
        "query": {
            "match": {
                "data.win.system.eventID": "22"
            }
        }
    }
}
