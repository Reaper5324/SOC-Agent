def parse_conn_log(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.startswith("#"):
                continue

            fields = line.split()
            if len(fields) < 7:
                continue

            event = {
                "timestamp": fields[0],
                "uid": fields[1],
                "src_ip": fields[2],
                "src_port": fields[3],
                "dest_ip": fields[4],
                "dest_port": fields[5],
                "protocol": fields[6].lower(),
                "service": fields[7] if len(fields) > 7 else None,
                "event_type": "connection",
                "description": "Network connection event",
                "severity": "low",
                "severity_score": 4,
                "source_tool": "Zeek",
            }
            events.append(event)

    return events
