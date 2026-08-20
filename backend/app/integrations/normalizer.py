def normalize_wazuh_alert(alert: dict) -> dict:

    data = alert.get("data", {})
    win = data.get("win", {})

    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    event_id = str(
        system.get("eventID", "")
    )

    provider = system.get(
        "providerName",
        ""
    )

    process_path = (
        eventdata.get("image")
        or ""
    )

    process_name = (
        process_path.split("\\")[-1]
        if process_path
        else ""
    )

    parent_path = (
        eventdata.get("parentImage")
        or ""
    )

    parent_process = (
        parent_path.split("\\")[-1]
        if parent_path
        else ""
    )

    command_line = (
        eventdata.get("commandLine")
        or ""
    )

    destination_ip = (
        eventdata.get("destinationIp")
        or eventdata.get("destinationIP")
        or ""
    )

    destination_port = (
        eventdata.get("destinationPort")
        or ""
    )

    source_ip = (
        eventdata.get("sourceIp")
        or eventdata.get("sourceIP")
        or ""
    )

    query_name = (
        eventdata.get("queryName")
        or ""
    )

    # Sysmon Event ID 1 = Process Creation
    if event_id == "1":
        event_type = "process_creation"

    # Sysmon Event ID 3 = Network Connection
    elif event_id == "3":
        event_type = "network_connection"

    # Sysmon Event ID 22 = DNS Query
    elif event_id == "22":
        event_type = "dns_query"

    elif process_name:
        event_type = "process_creation"

    elif destination_ip:
        event_type = "network_connection"

    else:
        event_type = "windows_event"

    return {
        "event_type": event_type,

        "event_id": event_id,

        "provider": provider,

        "process_name": process_name,

        "parent_process": parent_process,

        "command_line": command_line,

        "source_ip": source_ip,

        "destination_ip": destination_ip,

        "destination_port": destination_port,

        "query_name": query_name,

        "agent_id": alert.get(
            "agent", {}
        ).get("id"),

        "agent_name": alert.get(
            "agent", {}
        ).get("name"),

        "timestamp": (
            alert.get("@timestamp")
            or alert.get("timestamp")
        ),

        "rule_id": alert.get(
            "rule", {}
        ).get("id"),

        "wazuh_level": alert.get(
            "rule", {}
        ).get("level"),

        "rule_description": alert.get(
            "rule", {}
        ).get("description"),

        "raw_alert": alert
    }
