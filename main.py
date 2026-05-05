from pathlib import Path

from agent.analyst import analyse
from config import get_config
from Detection.rules import apply_rules
from parsers.suricata_parser import parse_eve
from parsers.zeek_parser import parse_conn_log
from utils.logger import get_logger


BASE_DIR = Path(__file__).resolve().parent
logger = get_logger(__name__)


def write_report(findings, report_path):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["SOC Agent Analysis Report", "=" * 26, ""]

    if not findings:
        lines.append("No suspicious events were detected.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.append(f"Incident {index}: {finding['incident_name']}")
            lines.append(f"Severity: {finding['severity']}")
            lines.append(
                f"Analysis source: {finding.get('analysis_source', 'fallback')}"
            )
            lines.append(f"Related events: {finding['event_count']}")
            lines.append(
                "Escalation required: "
                + ("Yes" if finding["escalation_required"] else "No")
            )
            lines.append(f"Why it matters: {finding['why_it_matters']}")
            lines.append("Next actions:")
            for action in finding["next_actions"]:
                lines.append(f"- {action}")
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    config = get_config()

    logger.info("SOC Agent starting...")
    logger.info("Ollama enabled: %s", config["ollama_enabled"])

    logger.info("Parsing Zeek logs...")
    zeek_events = parse_conn_log(str(BASE_DIR / "Data" / "zeek" / "conn.log"))
    logger.info("Zeek events loaded: %s", len(zeek_events))

    logger.info("Parsing Suricata logs...")
    suricata_events = parse_eve(str(BASE_DIR / "Data" / "suricata" / "eve.json"))
    logger.info("Suricata events loaded: %s", len(suricata_events))

    all_events = zeek_events + suricata_events

    logger.info("Applying detection rules...")
    suspicious_events = apply_rules(all_events)
    logger.info("Suspicious events detected: %s", len(suspicious_events))

    findings = analyse(suspicious_events)

    output_path = BASE_DIR / "output" / "report.txt"
    write_report(findings, output_path)
    logger.info("Incidents generated: %s", len(findings))
    logger.info("Report appended to %s", output_path.name)


if __name__ == "__main__":
    main()
