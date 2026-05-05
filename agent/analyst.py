import json
from collections import defaultdict

from agent.ollama_client import generate_incident_summary
from config import get_config
from utils.logger import get_logger


SEVERITY_LABELS = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
    5: "informational",
}

logger = get_logger(__name__)


def normalise_severity(event):
    if isinstance(event.get("severity_score"), int):
        return event["severity_score"]

    severity = str(event.get("severity", "")).lower()
    if severity.isdigit():
        return int(severity)

    reverse_map = {label: score for score, label in SEVERITY_LABELS.items()}
    return reverse_map.get(severity, 4)


def severity_label(score):
    return SEVERITY_LABELS.get(score, "unknown")


def analyse(events):
    incidents = defaultdict(list)

    for event in events:
        key = (
            event.get("src_ip", "unknown"),
            event.get("dest_ip", "unknown"),
            event.get("event_type", "unknown"),
        )
        incidents[key].append(event)

    findings = []
    config = get_config()
    ollama_enabled = config["ollama_enabled"]
    ollama_host = config["ollama_host"]
    ollama_model = config["ollama_model"]
    ollama_timeout = config["ollama_timeout"]

    logger.info("Analysing %s suspicious events into incidents...", len(events))

    for (src_ip, dest_ip, event_type), grouped_events in incidents.items():
        highest_score = min(normalise_severity(event) for event in grouped_events)
        first_event = grouped_events[0]
        finding = _build_fallback_finding(
            src_ip, dest_ip, event_type, grouped_events, first_event, highest_score
        )

        logger.info(
            "Analysing incident: %s | %s -> %s",
            event_type,
            src_ip,
            dest_ip,
        )

        if ollama_enabled:
            try:
                logger.info("Sending to Ollama - model: %s", ollama_model)
                llm_finding = _analyse_with_ollama(
                    grouped_events,
                    finding,
                    ollama_host,
                    ollama_model,
                    ollama_timeout,
                )
                finding.update(llm_finding)
                finding["analysis_source"] = "ollama"
                logger.info("Ollama analysis completed for %s -> %s", src_ip, dest_ip)
            except RuntimeError as exc:
                finding["analysis_source"] = f"fallback ({exc})"
                logger.warning(
                    "Ollama analysis failed for %s -> %s: %s",
                    src_ip,
                    dest_ip,
                    exc,
                )
        else:
            finding["analysis_source"] = "fallback (OLLAMA_ENABLED=false)"
            logger.info("Skipping Ollama analysis because it is disabled.")

        findings.append(finding)

    findings.sort(
        key=lambda finding: (finding["severity_score"], -finding["event_count"])
    )
    return findings


def _recommended_actions(event, highest_score):
    actions = []
    source_tool = event.get("source_tool", "").lower()
    protocol = event.get("protocol", "").lower()

    if source_tool == "suricata":
        actions.append("Validate the alert against surrounding network telemetry.")
        actions.append("Identify the affected host owner and review recent process activity.")

    if protocol == "udp":
        actions.append("Confirm whether the UDP destination and service are expected.")

    if highest_score <= 2:
        actions.append("Escalate to incident response for containment review.")
    else:
        actions.append("Continue triage and tune detections if activity is benign.")

    return actions


def _build_fallback_finding(
    src_ip, dest_ip, event_type, grouped_events, first_event, highest_score
):
    escalation_required = highest_score <= 2 or len(grouped_events) >= 3
    return {
        "incident_name": f"{event_type.title()} activity from {src_ip} to {dest_ip}",
        "severity_score": highest_score,
        "severity": severity_label(highest_score),
        "event_count": len(grouped_events),
        "escalation_required": escalation_required,
        "why_it_matters": first_event.get("description", "Suspicious activity detected"),
        "next_actions": _recommended_actions(first_event, highest_score),
        "events": grouped_events,
    }


def _analyse_with_ollama(
    grouped_events, fallback_finding, ollama_host, ollama_model, ollama_timeout
):
    prompt = _build_incident_prompt(grouped_events, fallback_finding)
    response = generate_incident_summary(
        ollama_host, ollama_model, prompt, timeout=ollama_timeout
    )

    next_actions = response.get("next_actions", fallback_finding["next_actions"])
    if not isinstance(next_actions, list) or not next_actions:
        next_actions = fallback_finding["next_actions"]

    severity = str(response.get("severity", fallback_finding["severity"])).lower()
    severity_score = _severity_score_from_label(severity)

    return {
        "incident_name": response.get(
            "incident_name", fallback_finding["incident_name"]
        ),
        "severity": severity_label(severity_score),
        "severity_score": severity_score,
        "escalation_required": bool(
            response.get(
                "escalation_required", fallback_finding["escalation_required"]
            )
        ),
        "why_it_matters": response.get(
            "why_it_matters", fallback_finding["why_it_matters"]
        ),
        "next_actions": [str(action) for action in next_actions],
    }


def _build_incident_prompt(grouped_events, fallback_finding):
    event_context = json.dumps(grouped_events, indent=2)
    return f"""
You are a SOC analyst helping triage suspicious security events.

Review the incident data below and respond with JSON only.
Use this exact schema:
{{
  "incident_name": "short title",
  "severity": "critical|high|medium|low|informational",
  "escalation_required": true,
  "Make reference to Cyber security frameworks like MITRE ATT&CK, OWASP etc.. where relevant.": "",
  "why_it_matters": "one short paragraph",
  "next_actions": ["action 1", "action 2", "action 3"]
}}

Ground your response only in the provided events.
If you are uncertain, stay conservative and avoid inventing facts.

Suggested baseline severity: {fallback_finding["severity"]}
Suggested escalation: {str(fallback_finding["escalation_required"]).lower()}

Incident events:
{event_context}
""".strip()


def _severity_score_from_label(severity):
    reverse_map = {label: score for score, label in SEVERITY_LABELS.items()}

    if severity.isdigit():
        return int(severity)

    return reverse_map.get(severity, 4)
