import json


def parse_eve(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if record.get("event_type") != "alert":
                continue

            alert = record.get("alert", {})
            event = {
                "timestamp": record.get("timestamp"),
                "src_ip": record.get("src_ip"),
                "src_port": record.get("src_port"),
                "dest_ip": record.get("dest_ip"),
                "dest_port": record.get("dest_port"),
                "protocol": str(record.get("proto", "")).lower(),
                "event_type": "alert",
                "description": alert.get("signature", "Suricata alert"),
                "severity": str(alert.get("severity", "unknown")),
                "severity_score": int(alert.get("severity", 3)),
                "signature_id": alert.get("signature_id"),
                "source_tool": "Suricata",
            }
            events.append(event)

    return events
