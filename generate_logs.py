#!/usr/bin/env python3
"""
generate_logs.py — Synthetic Windows Event Log generator.

Simulates a mid-size enterprise fleet (~10,000 endpoints over 30 days) and
writes realistic Windows Security / System / Application event records to CSV.

The output is *synthetic but statistically realistic*: normal baseline patterns
(logons, service starts, app crashes) plus five injected incident scenarios
that the ML detector is designed to catch:

  1. BRUTE_FORCE   — 47 failed logons in 3 minutes against one host (Event 4625)
  2. OFFHOURS_ADMIN — domain-admin logons at 3 AM from an unusual workstation
  3. RANSOMWARE    — rapid mass file-rename/encryption pattern + shadow-copy deletion
  4. SERVICE_OUTAGE — cascading service failures across 200+ hosts (bad patch)
  5. PROCESS_CHAIN — suspicious process tree: winword.exe -> powershell.exe -> mimikatz-like

Usage:
    python generate_logs.py                    # writes sample_logs/events.csv
    python generate_logs.py --hosts 500 --days 7 --out data/events.csv
"""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Event catalog — mirrors real Windows Event IDs and their meaning
# ---------------------------------------------------------------------------
EVENT_CATALOG = {
    4624: ("Security", "An account was successfully logged on"),
    4625: ("Security", "An account failed to log on"),
    4634: ("Security", "An account was logged off"),
    4672: ("Security", "Special privileges assigned to new logon"),
    4688: ("Security", "A new process has been created"),
    4697: ("Security", "A service was installed in the system"),
    4698: ("Security", "A scheduled task was created"),
    4700: ("Security", "A scheduled task was enabled"),
    4720: ("Security", "A user account was created"),
    4732: ("Security", "A member was added to a security-enabled local group"),
    4768: ("Security", "A Kerberos authentication ticket (TGT) was requested"),
    4769: ("Security", "A Kerberos service ticket was requested"),
    4771: ("Security", "Kerberos pre-authentication failed"),
    4776: ("Security", "The computer attempted to validate credentials (NTLM)"),
    5140: ("Security", "A network share object was accessed"),
    5156: ("Security", "Windows Filtering Platform allowed a connection"),
    1102: ("Security", "The audit log was cleared"),
    7045: ("System",   "A service was installed in the system"),
    7036: ("System",   "A service entered the running/stopped state"),
    7031: ("System",   "A service terminated unexpectedly"),
    7034: ("System",   "A service terminated unexpectedly (crash)"),
    6005: ("System",   "The Event log service was started"),
    6006: ("System",   "The Event log service was stopped"),
    1074: ("System",   "System shutdown/restart initiated"),
    1000: ("Application", "Application Error (crash)"),
    1001: ("Application", "Windows Error Reporting bucket"),
    1002: ("Application", "Application Hang"),
}

COMMON_PROCESSES = [
    "svchost.exe", "explorer.exe", "chrome.exe", "msedge.exe", "outlook.exe",
    "teams.exe", "winword.exe", "excel.exe", "notepad.exe", "dllhost.exe",
    "searchindexer.exe", "onedrive.exe", "spoolsv.exe", "lsass.exe",
    "csrss.exe", "winlogon.exe", "dwm.exe", "sihost.exe",
]

COMMON_SERVICES = [
    "Spooler", "wuauserv", "BITS", "Winmgmt", "Dhcp", "Dnscache",
    "LanmanServer", "Schedule", "Themes", "Audiosrv", "EventLog",
]

DEPARTMENTS = ["FIN", "HR", "ENG", "SALES", "IT", "OPS"]

# ---------------------------------------------------------------------------
# Fleet helpers
# ---------------------------------------------------------------------------

def make_fleet(n_hosts: int, rng: random.Random) -> list[dict]:
    """Build a list of host records with plausible naming + users."""
    fleet = []
    for i in range(n_hosts):
        dept = rng.choice(DEPARTMENTS)
        host = f"WS-{dept}-{1000 + i}"
        user = f"{dept.lower()}.user{1000 + i}"
        # Realistic: each host keeps 1-2 stable IPs (DHCP lease), not a random
        # IP per event. Random-per-event IPs create spurious "unique IP" noise
        # that drowns out real anomalies in the ML model.
        subnet = rng.randint(1, 9)
        ips = [f"10.{subnet}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
               for _ in range(rng.randint(1, 2))]
        fleet.append({"host": host, "user": user, "dept": dept, "ips": ips})
    # A couple of well-known servers + one domain admin for the story
    fleet.append({"host": "SRV-FILE-01", "user": "svc.backup", "dept": "IT",
                  "ips": ["10.9.0.11"]})
    fleet.append({"host": "SRV-DC-01", "user": "admin.rittu", "dept": "IT",
                  "ips": ["10.9.0.10"]})
    return fleet


def business_hour_weight(hour: int) -> float:
    """Probability weight for an event occurring at a given hour (0-23)."""
    if 8 <= hour <= 18:
        return 1.0
    if 6 <= hour <= 22:
        return 0.25
    return 0.05  # night: very quiet


# ---------------------------------------------------------------------------
# Baseline (normal) event generation
# ---------------------------------------------------------------------------

def gen_baseline(
    fleet: list[dict], start: datetime, days: int,
    rng: random.Random, events_per_host_day: int = 40,
) -> list[dict]:
    """Generate normal background noise for every host."""
    rows: list[dict] = []
    event_id = 0
    for day in range(days):
        day_start = start + timedelta(days=day)
        for h in fleet:
            n = rng.randint(events_per_host_day // 2, events_per_host_day)
            for _ in range(n):
                # Pick an hour weighted toward business hours
                hours = list(range(24))
                weights = [business_hour_weight(hh) for hh in hours]
                hour = rng.choices(hours, weights=weights, k=1)[0]
                ts = day_start + timedelta(
                    hours=hour,
                    minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
                eid = rng.choices(
                    [4624, 4624, 4624, 4634, 4688, 4688, 5156, 7036, 4768, 4769,
                     1000, 5140, 4776, 6005],
                    k=1,
                )[0]
                log, desc = EVENT_CATALOG[eid]
                proc = rng.choice(COMMON_PROCESSES) if eid == 4688 else ""
                rows.append({
                    "event_id": event_id,
                    "timestamp": ts.isoformat(timespec="seconds"),
                    "host": h["host"],
                    "user": h["user"],
                    "event_code": eid,
                    "log": log,
                    "description": desc,
                    "process": proc,
                    "source_ip": rng.choice(h["ips"]),
                    "is_injected": 0,
                    "scenario": "",
                })
                event_id += 1
    return rows


# ---------------------------------------------------------------------------
# Injected incident scenarios (the fun part)
# ---------------------------------------------------------------------------

def inject_brute_force(fleet, start, rng, rows, next_id) -> int:
    """Scenario 1: password-spray / brute force against a single workstation."""
    target = rng.choice([h for h in fleet if h["host"].startswith("WS-FIN")])
    base = start + timedelta(days=rng.randint(5, 25), hours=rng.randint(1, 4))
    attacker_ip = f"185.220.{rng.randint(0,255)}.{rng.randint(2,254)}"
    for i in range(47):
        ts = base + timedelta(seconds=i * rng.randint(2, 5))
        rows.append({
            "event_id": next_id, "timestamp": ts.isoformat(timespec="seconds"),
            "host": target["host"], "user": target["user"],
            "event_code": 4625, "log": "Security",
            "description": EVENT_CATALOG[4625][1],
            "process": "", "source_ip": attacker_ip,
            "is_injected": 1, "scenario": "BRUTE_FORCE",
        })
        next_id += 1
    # ...followed by ONE successful logon (the attacker got in)
    ts = base + timedelta(minutes=4)
    rows.append({
        "event_id": next_id, "timestamp": ts.isoformat(timespec="seconds"),
        "host": target["host"], "user": target["user"],
        "event_code": 4624, "log": "Security",
        "description": EVENT_CATALOG[4624][1],
        "process": "", "source_ip": attacker_ip,
        "is_injected": 1, "scenario": "BRUTE_FORCE",
    })
    return next_id + 1


def inject_offhours_admin(fleet, start, rng, rows, next_id) -> int:
    """Scenario 2: domain admin logging on at 3 AM from an odd workstation."""
    ws = rng.choice([h for h in fleet if h["host"].startswith("WS-SALES")])
    for night in range(3):  # three nights in a row — a pattern, not a fluke
        base = start + timedelta(days=10 + night, hours=3, minutes=rng.randint(0, 40))
        for eid in (4768, 4769, 4624, 4672):
            ts = base + timedelta(seconds=rng.randint(0, 120))
            rows.append({
                "event_id": next_id, "timestamp": ts.isoformat(timespec="seconds"),
                "host": ws["host"], "user": "admin.rittu",
                "event_code": eid, "log": "Security",
                "description": EVENT_CATALOG[eid][1],
                "process": "", "source_ip": "10.9.44.12",
                "is_injected": 1, "scenario": "OFFHOURS_ADMIN",
            })
            next_id += 1
    return next_id


def inject_ransomware(fleet, start, rng, rows, next_id) -> int:
    """Scenario 3: ransomware-like file encryption burst + shadow copy deletion."""
    target = rng.choice([h for h in fleet if h["host"].startswith("WS-ENG")])
    base = start + timedelta(days=rng.randint(12, 22), hours=rng.randint(9, 15))
    # Mass file access events (5140) — hundreds of files touched in minutes
    for i in range(320):
        ts = base + timedelta(seconds=i * rng.uniform(0.2, 0.8))
        rows.append({
            "event_id": next_id, "timestamp": ts.isoformat(timespec="seconds"),
            "host": target["host"], "user": target["user"],
            "event_code": 5140, "log": "Security",
            "description": "A network share object was accessed (mass file rename)",
            "process": "ransom_cryptor.exe", "source_ip": "",
            "is_injected": 1, "scenario": "RANSOMWARE",
        })
        next_id += 1
    # Attacker deletes shadow copies to block recovery (4688 with vssadmin)
    ts = base + timedelta(minutes=6)
    rows.append({
        "event_id": next_id, "timestamp": ts.isoformat(timespec="seconds"),
        "host": target["host"], "user": target["user"],
        "event_code": 4688, "log": "Security",
        "description": EVENT_CATALOG[4688][1],
        "process": "vssadmin.exe delete shadows /all /quiet",
        "source_ip": "",
        "is_injected": 1, "scenario": "RANSOMWARE",
    })
    return next_id + 1


def inject_service_outage(fleet, start, rng, rows, next_id) -> int:
    """Scenario 4: bad patch causes cascading service crashes fleet-wide."""
    victims = rng.sample(fleet, k=min(220, len(fleet)))
    base = start + timedelta(days=rng.randint(15, 25), hours=2, minutes=15)
    for v in victims:
        for j in range(rng.randint(2, 5)):
            ts = base + timedelta(minutes=rng.randint(0, 45), seconds=rng.randint(0, 59))
            eid = rng.choice([7031, 7034, 7034])
            rows.append({
                "event_id": next_id, "timestamp": ts.isoformat(timespec="seconds"),
                "host": v["host"], "user": v["user"],
                "event_code": eid, "log": "System",
                "description": EVENT_CATALOG[eid][1],
                "process": rng.choice(COMMON_SERVICES), "source_ip": "",
                "is_injected": 1, "scenario": "SERVICE_OUTAGE",
            })
            next_id += 1
    return next_id


def inject_process_chain(fleet, start, rng, rows, next_id) -> int:
    """Scenario 5: malicious process tree — winword -> powershell -> credential dump."""
    target = rng.choice([h for h in fleet if h["host"].startswith("WS-HR")])
    base = start + timedelta(days=rng.randint(8, 20), hours=rng.randint(10, 16))
    chain = [
        (4688, "winword.exe", "user opened attachment"),
        (4688, "powershell.exe -enc SQBmAHgA...", "encoded powershell spawned by winword"),
        (4688, "mimikatz_dump.exe", "credential dumping tool"),
        (1102, "", "security log cleared to hide tracks"),
    ]
    for eid, proc, _note in chain:
        ts = base + timedelta(seconds=rng.randint(5, 90))
        base = ts
        rows.append({
            "event_id": next_id, "timestamp": ts.isoformat(timespec="seconds"),
            "host": target["host"], "user": target["user"],
            "event_code": eid, "log": "Security",
            "description": EVENT_CATALOG[eid][1],
            "process": proc, "source_ip": "",
            "is_injected": 1, "scenario": "PROCESS_CHAIN",
        })
        next_id += 1
    return next_id


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Generate synthetic Windows Event Logs")
    ap.add_argument("--hosts", type=int, default=100,
                    help="Number of simulated endpoints (default 100; "
                         "scales to 10000 for the full demo)")
    ap.add_argument("--days", type=int, default=30,
                    help="Days of history to simulate (default 30)")
    ap.add_argument("--out", type=str, default="sample_logs/events.csv",
                    help="Output CSV path")
    ap.add_argument("--seed", type=int, default=42,
                    help="Random seed for reproducible demos")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    start = datetime.now() - timedelta(days=args.days)

    print(f"[+] Building fleet of {args.hosts} endpoints over {args.days} days...")
    fleet = make_fleet(args.hosts, rng)

    print("[+] Generating baseline (normal) activity...")
    rows = gen_baseline(fleet, start, args.days, rng)
    next_id = len(rows)

    print("[+] Injecting 5 incident scenarios...")
    next_id = inject_brute_force(fleet, start, rng, rows, next_id)
    next_id = inject_offhours_admin(fleet, start, rng, rows, next_id)
    next_id = inject_ransomware(fleet, start, rng, rows, next_id)
    next_id = inject_service_outage(fleet, start, rng, rows, next_id)
    next_id = inject_process_chain(fleet, start, rng, rows, next_id)

    # Sort chronologically — just like a real SIEM export would be
    rows.sort(key=lambda r: r["timestamp"])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    injected = sum(1 for r in rows if r["is_injected"])
    print(f"[+] Wrote {len(rows):,} events ({injected:,} injected anomalies) -> {out}")


if __name__ == "__main__":
    main()
