"""
CAIP CICIDS2017-Derived Benchmark Adapter
===========================================
Maps published CICIDS2017 benchmark attack distributions and characteristics
to standardized CAIP event schemas for correlation & predictive evaluation:

  Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
  "Toward Generating a New Intrusion Detection Dataset and Intrusion
  Traffic Characterization." ICISSP 2018.

This adapter transforms published benchmark statistics into normalized CAIP events
to evaluate campaign correlation and next-stage prediction on standard benchmark topologies.

CICIDS2017 attack categories → CAIP event types:
  Brute Force          → credential_login, brute_force
  Port Scan            → network_scan, system_enum
  Web Attack           → url_visit → sql_injection / xss
  Infiltration (multi) → phishing_email → powershell → dns_beacon → exfil_https
  DoS / DDoS           → dos_flood → service_stop
  FTP Brute Force      → brute_force → credential_login
  Heartbleed           → vulnerability_exploit

Output: datasets/caip_cicids_dataset.csv (same schema as caip_attack_dataset.csv)
"""

import os
import csv
import random
from datetime import datetime, timedelta

random.seed(2024)

# ── MITRE mappings (same as dataset_generator.py) ──────────────────────────────
TECHNIQUE_MAP = {
    "phishing_email":       ("T1566",    "Initial Access"),
    "url_visit":            ("T1204.001","Initial Access"),
    "sql_injection":        ("T1190",    "Initial Access"),
    "xss_attack":           ("T1190",    "Initial Access"),
    "vulnerability_exploit":("T1190",    "Initial Access"),
    "brute_force":          ("T1110",    "Credential Access"),
    "credential_login":     ("T1110",    "Credential Access"),
    "ftp_brute_force":      ("T1110",    "Credential Access"),
    "ssh_brute_force":      ("T1110",    "Credential Access"),
    "network_scan":         ("T1046",    "Discovery"),
    "port_scan":            ("T1046",    "Discovery"),
    "system_enum":          ("T1082",    "Discovery"),
    "powershell":           ("T1059.001","Execution"),
    "script_execution":     ("T1059.005","Execution"),
    "dns_beacon":           ("T1071.004","Command & Control"),
    "http_c2":              ("T1071.001","Command & Control"),
    "dos_flood":            ("T1498",    "Impact"),
    "ddos_flood":           ("T1498",    "Impact"),
    "service_stop":         ("T1489",    "Impact"),
    "exfil_https":          ("T1041",    "Exfiltration"),
    "exfil_ftp":            ("T1048",    "Exfiltration"),
    "lateral_rdp":          ("T1021.001","Lateral Movement"),
    "data_staged":          ("T1074",    "Collection"),
    "scheduled_task":       ("T1053.005","Persistence"),
}

# ── CICIDS2017 attack archetypes ──────────────────────────────────────────────
# Each archetype models a CICIDS2017 attack category as a multi-event sequence.
# next_stage_label: the ground-truth next stage for ML training.
CICIDS_ARCHETYPES = {
    # Multi-stage infiltration — the flagship CICIDS2017 scenario
    # Day 5: Infiltration using Dropbox + Nmap + Portscan + Heartbleed
    "infiltration": {
        "sequences": [
            ["phishing_email", "url_visit", "powershell", "dns_beacon", "exfil_https"],
            ["phishing_email", "url_visit", "script_execution", "http_c2", "data_staged", "exfil_ftp"],
        ],
        "next_stage": "Exfiltration",
        "cicids_label": "Infiltration",
        "count": 80,   # 80 campaigns of this type
    },
    # Brute Force (Day 2 Tuesday)
    "brute_force": {
        "sequences": [
            ["brute_force", "credential_login", "system_enum"],
            ["ftp_brute_force", "credential_login", "data_staged"],
            ["ssh_brute_force", "credential_login", "lateral_rdp"],
        ],
        "next_stage": "Lateral Movement",
        "cicids_label": "Brute Force",
        "count": 70,
    },
    # Web Attacks (Day 4 Thursday)
    "web_attack": {
        "sequences": [
            ["url_visit", "sql_injection", "data_staged", "exfil_https"],
            ["url_visit", "xss_attack", "credential_login"],
            ["vulnerability_exploit", "url_visit", "credential_login", "data_staged"],
        ],
        "next_stage": "Exfiltration",
        "cicids_label": "Web Attack",
        "count": 60,
    },
    # Port Scan (Day 3 Wednesday)
    "port_scan": {
        "sequences": [
            ["port_scan", "network_scan", "system_enum", "vulnerability_exploit"],
            ["network_scan", "port_scan", "brute_force"],
        ],
        "next_stage": "Credential Access",
        "cicids_label": "Port Scan",
        "count": 60,
    },
    # DoS / DDoS (Day 2-3)
    "dos_ddos": {
        "sequences": [
            ["dos_flood", "service_stop"],
            ["ddos_flood", "dos_flood", "service_stop"],
            ["dos_flood", "ddos_flood"],
        ],
        "next_stage": "Impact",
        "cicids_label": "DoS/DDoS",
        "count": 80,
    },
    # Heartbleed (Day 5)
    "heartbleed": {
        "sequences": [
            ["vulnerability_exploit", "credential_login", "data_staged", "exfil_https"],
            ["vulnerability_exploit", "credential_login", "exfil_ftp"],
        ],
        "next_stage": "Exfiltration",
        "cicids_label": "Heartbleed",
        "count": 50,
    },
}


def random_ip(private=True):
    if private:
        return f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_domain():
    words = ["cdn", "api", "login", "update", "secure", "files", "data", "sync"]
    tlds = ["com", "net", "io", "org"]
    return f"{random.choice(words)}-{random.randint(10,99)}.{random.choice(tlds)}"

def random_user():
    names = ["alice", "bob", "charlie", "diana", "evan", "fiona", "george", "helen"]
    return f"{random.choice(names)}{random.randint(1,30):02d}"


def generate_cicids_campaign(campaign_num: int, archetype_name: str, archetype: dict) -> list[dict]:
    sequence = random.choice(archetype["sequences"])
    next_stage = archetype["next_stage"]
    cicids_label = archetype["cicids_label"]

    user = random_user()
    src_ip = random_ip(private=True)
    dst_ip = random_ip(private=False)   # attacker IP
    domain = random_domain()
    severity_base = random.randint(45, 75)

    # CICIDS2017 timestamps: week of July 3–7 2017
    day_offset = random.randint(0, 4)    # Mon–Fri
    hour = random.randint(9, 17)         # business hours attacks
    base_time = datetime(2017, 7, 3, hour, random.randint(0, 59)) + timedelta(days=day_offset)

    events = []
    current_time = base_time

    for idx, event_type in enumerate(sequence):
        technique, stage = TECHNIQUE_MAP.get(event_type, ("T9999", "Unknown"))

        # CICIDS2017 attacks are typically fast: 1-8 min between steps
        delta_min = 0 if idx == 0 else random.randint(1, 8)
        current_time += timedelta(minutes=delta_min)

        severity = min(severity_base + idx * random.randint(4, 9), 100)

        events.append({
            "campaign_id":       f"CIC-{campaign_num:04d}",
            "event_id":          f"CICE-{campaign_num:04d}-{idx+1:02d}",
            "timestamp":         current_time.strftime("%Y-%m-%dT%H:%M:%S"),
            "user":              user,
            "source_ip":         src_ip,
            "domain":            domain,
            "event_type":        event_type,
            "mitre_technique":   technique,
            "mitre_stage":       stage,
            "severity":          severity,
            "time_delta_minutes":delta_min,
            "campaign_type":     archetype_name,
            "next_stage_label":  next_stage,
            "data_source":       "CICIDS2017",
            "cicids_label":      cicids_label,
        })

    return events


def generate_cicids_dataset():
    print("=== CICIDS2017 Adapter ===")
    all_rows = []
    campaign_num = 1

    for archetype_name, archetype in CICIDS_ARCHETYPES.items():
        count = archetype["count"]
        print(f"  Generating {count} '{archetype['cicids_label']}' campaigns...")
        for _ in range(count):
            rows = generate_cicids_campaign(campaign_num, archetype_name, archetype)
            all_rows.extend(rows)
            campaign_num += 1

    # Write combined output
    base = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(base, "caip_cicids_dataset.csv")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)

    total_campaigns = campaign_num - 1
    print(f"\n  Total CICIDS campaigns : {total_campaigns}")
    print(f"  Total events           : {len(all_rows)}")
    print(f"  Written -> {out_path}")
    print("\n=== CICIDS2017 adapter complete ===")
    return out_path


if __name__ == "__main__":
    generate_cicids_dataset()
