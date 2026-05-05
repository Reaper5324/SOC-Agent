def apply_rules(events):
    suspicious = []
    flagged = set()
    seen = set()

    for event in events:
        source_tool = event.get("source_tool", "").lower()
        event_type = event.get("event_type")
        protocol = event.get("protocol", "").lower()
        dest_port = str(event.get("dest_port", ""))

        if source_tool == "suricata" and event_type == "alert":
            _append_unique(suspicious, seen, event)
            continue

        if event_type == "connection" and protocol == "udp":
            enriched = dict(event)
            enriched["severity"] = "medium"
            enriched["severity_score"] = 3
            enriched["description"] = (
                f"UDP connection observed to {event.get('dest_ip')}:{dest_port}"
            )
            _append_unique(suspicious, seen, enriched)
            
        #if src_ip appears in 5 or more events within a 10 minute window, flag as suspicious
        if event_type == "connection":
            src_ip = event.get("src_ip")
            if src_ip in flagged:
                continue

            timestamp = _to_epoch_seconds(event.get("timestamp"))
            if timestamp is None:
                continue

            recent_events = [
                e for e in events
                if e.get("src_ip") == src_ip and
                _to_epoch_seconds(e.get("timestamp")) is not None and
                abs(_to_epoch_seconds(e.get("timestamp")) - timestamp) <= 600
            ]
            if len(recent_events) >= 5:
                enriched = dict(event)
                enriched["severity"] = "high"
                enriched["severity_score"] = 2
                enriched["event_type"] = "brute_force"
                enriched["description"] = (
                    f"Source IP {src_ip} has {len(recent_events)} connections within a 10 minute window. Potential Brute Force or Scanning activity."
                )
                _append_unique(suspicious, seen, enriched)
                flagged.add(src_ip)

    return suspicious


def _append_unique(suspicious, seen, event):
    event_key = (
        event.get("timestamp"),
        event.get("src_ip"),
        event.get("src_port"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("event_type"),
        event.get("signature_id"),
        event.get("description"),
    )

    if event_key in seen:
        return

    seen.add(event_key)
    suspicious.append(event)


def _to_epoch_seconds(timestamp):
    try:
        return float(timestamp)
    except (TypeError, ValueError):
        return None
