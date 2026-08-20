def normalize_hunt_result(hit: dict) -> dict:

    source = hit.get(
        "_source",
        {}
    )

    data = source.get(
        "data",
        {}
    )

    win = data.get(
        "win",
        {}
    )

    system = win.get(
        "system",
        {}
    )

    eventdata = win.get(
        "eventdata",
        {}
    )

    return {

        "timestamp": (
            source.get("@timestamp")
            or source.get("timestamp")
        ),

        "agent": source.get(
            "agent",
            {}
        ).get("name"),

        "event_id": system.get(
            "eventID"
        ),

        "provider": system.get(
            "providerName"
        ),

        "process": eventdata.get(
            "image"
        ),

        "command_line": eventdata.get(
            "commandLine"
        ),

        "source_ip": eventdata.get(
            "sourceIp"
        ),

        "destination_ip": eventdata.get(
            "destinationIp"
        ),

        "destination_port": eventdata.get(
            "destinationPort"
        ),

        "query_name": eventdata.get(
            "queryName"
        ),

        "rule_id": source.get(
            "rule",
            {}
        ).get("id"),

        "rule_description": source.get(
            "rule",
            {}
        ).get("description")
    }
