#!/usr/bin/env python3
"""Generate synthetic Windows endpoint artifacts for a simulated ransomware incident.

Produces four artifact files under artifacts/, modeled after real forensic
sources (Sysmon/Security event log, Prefetch, Registry Run keys, NTFS/$MFT
file activity). The event stream mixes the attack chain in with benign noise
processes, the way a real endpoint looks before triage.
"""
import argparse
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

ARTIFACT_DIR = Path("artifacts")

BASE_TIME = datetime(2026, 3, 11, 9, 14, 0)


def ts(offset_seconds):
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat()


def build_process_events():
    """Sysmon Event ID 1 (Process Creation) style records."""
    events = [
        # --- benign noise: normal morning activity ---
        {
            "timestamp": ts(-620), "event_id": 1, "image": "C:\\Windows\\explorer.exe",
            "command_line": "C:\\Windows\\explorer.exe",
            "parent_image": "C:\\Windows\\System32\\userinit.exe", "pid": 2104,
            "parent_pid": 1988, "user": "CORP\\j.morales",
            "sha256": "b3f1a9c2d4e5f60718293a4b5c6d7e8f9012345678901234567890abcdef012",
        },
        {
            "timestamp": ts(-300), "event_id": 1, "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
            "command_line": "\"OUTLOOK.EXE\"",
            "parent_image": "C:\\Windows\\explorer.exe", "pid": 3312,
            "parent_pid": 2104, "user": "CORP\\j.morales",
            "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abcdef0123",
        },
        # --- T1566.001: spearphishing attachment opened ---
        {
            "timestamp": ts(0), "event_id": 1, "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "command_line": "\"WINWORD.EXE\" /n \"C:\\Users\\j.morales\\Downloads\\Invoice_84421.docm\"",
            "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "pid": 4488,
            "parent_pid": 3312, "user": "CORP\\j.morales",
            "sha256": "c4d5e6f70819293a4b5c6d7e8f9012345678901234567890abcdef01234567",
        },
        # --- T1059.001 / T1204.002: macro spawns obfuscated PowerShell ---
        {
            "timestamp": ts(41), "event_id": 1, "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": (
                "powershell.exe -NoP -W Hidden -Exec Bypass -EncodedCommand "
                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn"
            ),
            "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "pid": 4602,
            "parent_pid": 4488, "user": "CORP\\j.morales",
            "sha256": "91af1c2b3e4d5c6b7a8f9e0d1c2b3a4958677654433221100ffeeddccbbaa9",
        },
        # --- T1105: payload retrieval ---
        {
            "timestamp": ts(53), "event_id": 3, "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "outbound connection to 185.220.101.47:443 (TLS)",
            "parent_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 4602,
            "parent_pid": 4488, "user": "CORP\\j.morales",
            "sha256": None,
        },
        {
            "timestamp": ts(58), "event_id": 1, "image": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe",
            "command_line": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe",
            "parent_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 4711,
            "parent_pid": 4602, "user": "CORP\\j.morales",
            "sha256": "7de4f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2",
        },
        # --- T1562.001: defense evasion, disable recovery/logging ---
        {
            "timestamp": ts(75), "event_id": 1, "image": "C:\\Windows\\System32\\vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "parent_image": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe", "pid": 4790,
            "parent_pid": 4711, "user": "CORP\\j.morales",
            "sha256": "d41d8cd98f00b204e9800998ecf8427e0000000000000000000000000000aa",
        },
        {
            "timestamp": ts(79), "event_id": 1, "image": "C:\\Windows\\System32\\wbadmin.exe",
            "command_line": "wbadmin.exe delete catalog -quiet",
            "parent_image": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe", "pid": 4803,
            "parent_pid": 4711, "user": "CORP\\j.morales",
            "sha256": "d41d8cd98f00b204e9800998ecf8427e0000000000000000000000000000bb",
        },
        # --- T1082 / T1018: discovery, benign-looking recon ---
        {
            "timestamp": ts(92), "event_id": 1, "image": "C:\\Windows\\System32\\whoami.exe",
            "command_line": "whoami.exe /all",
            "parent_image": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe", "pid": 4820,
            "parent_pid": 4711, "user": "CORP\\j.morales",
            "sha256": None,
        },
        {
            "timestamp": ts(95), "event_id": 1, "image": "C:\\Windows\\System32\\net.exe",
            "command_line": "net.exe view \\\\FS01-CORP",
            "parent_image": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe", "pid": 4830,
            "parent_pid": 4711, "user": "CORP\\j.morales",
            "sha256": None,
        },
        # --- T1486: impact, encryptor process ---
        {
            "timestamp": ts(140), "event_id": 1, "image": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe",
            "command_line": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe --encrypt --path=C:\\Users\\j.morales --path=\\\\FS01-CORP\\Shared",
            "parent_image": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe", "pid": 4711,
            "parent_pid": 4602, "user": "CORP\\j.morales",
            "sha256": "7de4f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2",
        },
        # --- benign noise: unrelated scheduled task around the same time ---
        {
            "timestamp": ts(-180), "event_id": 1, "image": "C:\\Windows\\System32\\taskhostw.exe",
            "command_line": "taskhostw.exe {WindowsUpdateCheck}",
            "parent_image": "C:\\Windows\\System32\\svchost.exe", "pid": 2990,
            "parent_pid": 900, "user": "NT AUTHORITY\\SYSTEM",
            "sha256": "0011223344556677889900112233445566778899001122334455667788aabb",
        },
    ]
    return sorted(events, key=lambda e: e["timestamp"])


def build_prefetch_artifacts():
    return [
        {"file": "WINWORD.EXE-3F2A1B0C.pf", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "run_count": 214, "first_run": ts(-86400 * 40), "last_run": ts(0)},
        {"file": "POWERSHELL.EXE-9A7C4E11.pf", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "run_count": 3, "first_run": ts(41), "last_run": ts(41)},
        {"file": "SVCHOST_UPD.EXE-1D5B8F02.pf", "path": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe",
         "run_count": 1, "first_run": ts(58), "last_run": ts(58)},
        {"file": "VSSADMIN.EXE-6C3E9A44.pf", "path": "C:\\Windows\\System32\\vssadmin.exe",
         "run_count": 2, "first_run": ts(-86400 * 200), "last_run": ts(75)},
    ]


def build_registry_persistence():
    return [
        {"hive": "HKCU", "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value_name": "OneDriveSync", "value_data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background",
         "last_write": ts(-86400 * 12), "legitimate": True},
        {"hive": "HKCU", "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value_name": "WindowsSvcHelper", "value_data": "C:\\Users\\j.morales\\AppData\\Local\\Temp\\svchost_upd.exe -silent",
         "last_write": ts(60), "legitimate": False},
    ]


def build_filesystem_activity():
    """Mass file rename burst representing the encryption stage, plus ransom notes."""
    rows = []
    directories = [
        "C:\\Users\\j.morales\\Documents", "C:\\Users\\j.morales\\Desktop",
        "C:\\Users\\j.morales\\Pictures", "\\\\FS01-CORP\\Shared\\Finance",
        "\\\\FS01-CORP\\Shared\\HR",
    ]
    extensions = [".docx", ".xlsx", ".pdf", ".pptx", ".jpg", ".csv"]
    file_id = 1
    t = 141
    for _ in range(180):
        directory = random.choice(directories)
        ext = random.choice(extensions)
        original = f"{directory}\\file_{file_id:04d}{ext}"
        renamed = f"{directory}\\file_{file_id:04d}{ext}.locked"
        rows.append({"timestamp": ts(t), "action": "rename", "original_path": original, "new_path": renamed})
        file_id += 1
        t += round(random.uniform(0.3, 1.4), 2)
    for directory in directories:
        rows.append({
            "timestamp": ts(t + 5), "action": "create",
            "original_path": "", "new_path": f"{directory}\\README_DECRYPT.txt",
        })
        t += 2
    return sorted(rows, key=lambda r: r["timestamp"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducible artifact generation")
    args = parser.parse_args()
    random.seed(args.seed)

    ARTIFACT_DIR.mkdir(exist_ok=True)

    with open(ARTIFACT_DIR / "sysmon_process_events.json", "w") as f:
        json.dump(build_process_events(), f, indent=2)

    with open(ARTIFACT_DIR / "prefetch_artifacts.json", "w") as f:
        json.dump(build_prefetch_artifacts(), f, indent=2)

    with open(ARTIFACT_DIR / "registry_persistence.json", "w") as f:
        json.dump(build_registry_persistence(), f, indent=2)

    fs_rows = build_filesystem_activity()
    with open(ARTIFACT_DIR / "filesystem_activity.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "action", "original_path", "new_path"])
        writer.writeheader()
        writer.writerows(fs_rows)

    print(f"Generated {len(build_process_events())} process events")
    print(f"Generated {len(build_prefetch_artifacts())} prefetch artifacts")
    print(f"Generated {len(build_registry_persistence())} registry entries")
    print(f"Generated {len(fs_rows)} filesystem activity records")
    print(f"Artifacts written to {ARTIFACT_DIR}/")


if __name__ == "__main__":
    main()
