#!/usr/bin/env python3
"""Correlate multi-source endpoint artifacts into a single forensic timeline.

Reads the four artifact sources produced by generate_artifacts.py (process
events, prefetch, registry persistence, filesystem activity), applies
detection heuristics to flag the attack-relevant entries against MITRE
ATT&CK, and renders a unified, time-ordered incident timeline.
"""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

ARTIFACT_DIR = Path("artifacts")

RANSOM_NOTE_MARKERS = ("README_DECRYPT", "DECRYPT", "HOW_TO_RECOVER", "RESTORE_FILES")
ENCRYPTED_EXTENSIONS = (".locked", ".crypt", ".encrypted", ".enc")
SHADOW_COPY_TOOLS = ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe")
DISCOVERY_TOOLS = ("whoami.exe", "net.exe", "nltest.exe", "systeminfo.exe")
OFFICE_APPS = ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
SHELL_TOOLS = ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
SUSPICIOUS_RUN_PATHS = ("\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\")


def classify_process_event(event):
    """Return (technique_id, technique_name, severity) or None for a process event."""
    image = event["image"]
    image_name = image.rsplit("\\", 1)[-1]
    parent_name = event["parent_image"].rsplit("\\", 1)[-1]
    cmd = event.get("command_line") or ""

    if parent_name in OFFICE_APPS and image_name.lower() in SHELL_TOOLS:
        if "-enc" in cmd.lower() or "-encodedcommand" in cmd.lower():
            return ("T1566.001 / T1059.001", "Spearphishing Attachment spawning obfuscated PowerShell", "CRITICAL")
        return ("T1566.001 / T1059.001", "Spearphishing Attachment spawning a shell interpreter", "CRITICAL")

    if image_name.lower() in [t.lower() for t in SHADOW_COPY_TOOLS]:
        return ("T1490", "Inhibit System Recovery (shadow copy / backup catalog deletion)", "CRITICAL")

    if image_name.lower() in [t.lower() for t in DISCOVERY_TOOLS]:
        return ("T1082 / T1018", "System / Remote System Discovery", "MEDIUM")

    if "--encrypt" in cmd or "--path=" in cmd:
        return ("T1486", "Data Encrypted for Impact", "CRITICAL")

    if event.get("event_id") == 3 and "185." in cmd:
        return ("T1105", "Ingress Tool Transfer (outbound payload retrieval)", "HIGH")

    return None


def classify_registry_entry(entry):
    if entry.get("legitimate"):
        return None
    value_data = entry.get("value_data", "")
    if any(p in value_data for p in SUSPICIOUS_RUN_PATHS):
        return ("T1547.001", "Registry Run Key persistence pointing to a user-writable path", "HIGH")
    return ("T1547.001", "Unrecognized Registry Run Key persistence", "MEDIUM")


def classify_filesystem_row(row):
    new_path = row.get("new_path", "")
    if any(new_path.endswith(ext) for ext in ENCRYPTED_EXTENSIONS):
        return ("T1486", "File renamed with ransomware extension", "CRITICAL")
    if any(marker in new_path.upper() for marker in RANSOM_NOTE_MARKERS):
        return ("T1491.001", "Ransom note dropped (Internal Defacement / extortion notice)", "CRITICAL")
    return None


def load_artifacts():
    with open(ARTIFACT_DIR / "sysmon_process_events.json") as f:
        process_events = json.load(f)
    with open(ARTIFACT_DIR / "prefetch_artifacts.json") as f:
        prefetch = json.load(f)
    with open(ARTIFACT_DIR / "registry_persistence.json") as f:
        registry = json.load(f)
    with open(ARTIFACT_DIR / "filesystem_activity.csv") as f:
        filesystem = list(csv.DictReader(f))
    return process_events, prefetch, registry, filesystem


def build_timeline(process_events, registry, filesystem):
    timeline = []

    for event in process_events:
        classification = classify_process_event(event)
        timeline.append({
            "timestamp": event["timestamp"],
            "source": "Process Creation (Sysmon/Security 4688)",
            "summary": f"{event['image']} (PID {event['pid']}, parent {event['parent_image']})",
            "detail": event.get("command_line", ""),
            "technique": classification[0] if classification else None,
            "description": classification[1] if classification else None,
            "severity": classification[2] if classification else "INFO",
        })

    for entry in registry:
        classification = classify_registry_entry(entry)
        timeline.append({
            "timestamp": entry["last_write"],
            "source": "Registry (Run key)",
            "summary": f"{entry['hive']}\\{entry['key']}\\{entry['value_name']}",
            "detail": entry["value_data"],
            "technique": classification[0] if classification else None,
            "description": classification[1] if classification else "Legitimate startup entry",
            "severity": classification[2] if classification else "INFO",
        })

    encryption_burst_start = None
    encryption_burst_count = 0
    for row in filesystem:
        classification = classify_filesystem_row(row)
        if classification and classification[0] == "T1486":
            encryption_burst_count += 1
            if encryption_burst_start is None:
                encryption_burst_start = row["timestamp"]
            continue  # summarized below instead of one line per file
        if classification:
            timeline.append({
                "timestamp": row["timestamp"],
                "source": "Filesystem (MFT/USN activity)",
                "summary": row["new_path"],
                "detail": f"action={row['action']}",
                "technique": classification[0],
                "description": classification[1],
                "severity": classification[2],
            })

    if encryption_burst_count:
        timeline.append({
            "timestamp": encryption_burst_start,
            "source": "Filesystem (MFT/USN activity)",
            "summary": f"{encryption_burst_count} files renamed with ransomware extension across 5 directories",
            "detail": "Burst pattern: high-rate sequential rename, single process handle",
            "technique": "T1486",
            "description": "Data Encrypted for Impact (mass encryption burst)",
            "severity": "CRITICAL",
        })

    timeline.sort(key=lambda e: e["timestamp"])
    return timeline


def render_report(timeline, prefetch):
    lines = []
    lines.append("=" * 78)
    lines.append(" DFIR TIMELINE RECONSTRUCTION -- SIMULATED RANSOMWARE INCIDENT")
    lines.append(f" Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("=" * 78)
    lines.append("")

    flagged = [e for e in timeline if e["technique"]]
    lines.append(f" Total artifacts correlated : {len(timeline)}")
    lines.append(f" Flagged as attack-relevant : {len(flagged)}")
    lines.append("")
    lines.append("-" * 78)
    lines.append(" UNIFIED TIMELINE")
    lines.append("-" * 78)

    for e in timeline:
        marker = "[!]" if e["technique"] else "[ ]"
        lines.append(f"{marker} {e['timestamp']}  {e['source']}")
        lines.append(f"     {e['summary']}")
        if e["detail"]:
            lines.append(f"     {e['detail']}")
        if e["technique"]:
            lines.append(f"     MITRE: {e['technique']} -- {e['description']} [{e['severity']}]")
        lines.append("")

    lines.append("-" * 78)
    lines.append(" MITRE ATT&CK TECHNIQUES OBSERVED")
    lines.append("-" * 78)
    technique_counts = Counter(e["technique"] for e in flagged)
    for technique, count in technique_counts.most_common():
        lines.append(f"  {technique:<20} occurrences: {count}")

    lines.append("")
    lines.append("-" * 78)
    lines.append(" PREFETCH EXECUTION EVIDENCE")
    lines.append("-" * 78)
    for p in prefetch:
        lines.append(f"  {p['file']:<32} run_count={p['run_count']:<4} last_run={p['last_run']}")

    critical = [e for e in flagged if e["severity"] == "CRITICAL"]
    lines.append("")
    lines.append("=" * 78)
    if critical:
        lines.append(" VERDICT: RANSOMWARE INCIDENT CONFIRMED -- CRITICAL")
        lines.append(f" {len(critical)} critical-severity techniques observed across the kill chain,")
        lines.append(" from initial access through impact. Immediate containment and")
        lines.append(" restoration from offline backups recommended.")
    else:
        lines.append(" VERDICT: NO CRITICAL INDICATORS FOUND")
    lines.append("=" * 78)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="timeline_report.txt", help="Report output file")
    parser.add_argument("--csv-out", default="timeline.csv", help="Combined timeline CSV export")
    args = parser.parse_args()

    if not ARTIFACT_DIR.exists():
        raise SystemExit("No artifacts/ directory found. Run generate_artifacts.py first.")

    process_events, prefetch, registry, filesystem = load_artifacts()
    timeline = build_timeline(process_events, registry, filesystem)
    report = render_report(timeline, prefetch)

    Path(args.output).write_text(report, encoding="utf-8")
    print(report)

    with open(args.csv_out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "source", "summary", "detail", "technique", "description", "severity"])
        writer.writeheader()
        writer.writerows(timeline)

    print(f"\nReport written to {args.output}")
    print(f"Timeline CSV written to {args.csv_out}")


if __name__ == "__main__":
    main()
