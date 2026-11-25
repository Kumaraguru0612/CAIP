"""
CAIP Multi-Scenario Attack Dataset Generator
=============================================
Produces realistic, labelled attack campaigns across 4 archetypes for
IEEE research. Each campaign has temporal variation, diverse users/IPs,
and ground-truth next_stage labels for ML training and validation.

Output:
  datasets/caip_attack_dataset.csv   — 480 campaigns (80% train split)
  datasets/caip_validation_set.csv   — 120 campaigns (20% hold-out)
"""

import os
import sys
import csv
import random
import uuid
from datetime import datetime, timedelta
from collections import defaultdict

random.seed(42)

# ── MITRE ATT&CK technique mappings ──────────────────────────────────────────
TECHNIQUE_MAP = {
    "phishing_email":       ("T1566",    "Initial Access"),
    "spear_phishing":       ("T1566.001","Initial Access"),
    "url_visit":            ("T1204.001","Initial Access"),
    "attachment_download":  ("T1204.002","Initial Access"),
    "drive_by":             ("T1189",    "Initial Access"),
    "powershell":           ("T1059.001","Execution"),
    "script_execution":     ("T1059.005","Execution"),
    "macro_execution":      ("T1204.002","Execution"),
    "wmi_execution":        ("T1047",    "Execution"),
    "scheduled_task":       ("T1053.005","Persistence"),
    "registry_run_key":     ("T1547.001","Persistence"),
    "startup_folder":       ("T1547.001","Persistence"),
    "log_clearing":         ("T1070",    "Defense Evasion"),
    "process_injection":    ("T1055",    "Defense Evasion"),
    "masquerading":         ("T1036",    "Defense Evasion"),
    "credential_login":     ("T1110",    "Credential Access"),
    "mimikatz":             ("T1003.001","Credential Access"),
    "kerberoasting":        ("T1558.003","Credential Access"),
    "suspicious_login":     ("T1078",    "Credential Access"),
    "suspicious_dns":       ("T1071.004","Command & Control"),
    "dns_beacon":           ("T1071.004","Command & Control"),
    "http_c2":              ("T1071.001","Command & Control"),
    "icmp_tunnel":          ("T1095",    "Command & Control"),
    "privilege_escalation": ("T1068",    "Privilege Escalation"),
    "uac_bypass":           ("T1548.002","Privilege Escalation"),
    "token_impersonation":  ("T1134",    "Privilege Escalation"),
    "network_scan":         ("T1046",    "Discovery"),
    "system_enum":          ("T1082",    "Discovery"),
    "file_search":          ("T1083",    "Discovery"),
    "lateral_rdp":          ("T1021.001","Lateral Movement"),
    "lateral_smb":          ("T1021.002","Lateral Movement"),
    "lateral_wmi":          ("T1021.006","Lateral Movement"),
    "data_staged":          ("T1074",    "Collection"),
    "keylogger":            ("T1056.001","Collection"),
    "screen_capture":       ("T1113",    "Collection"),
    "exfil_ftp":            ("T1048",    "Exfiltration"),
    "exfil_https":          ("T1041",    "Exfiltration"),
    "dns_exfil":            ("T1048.003","Exfiltration"),
    "ransomware_encrypt":   ("T1486",    "Impact"),
    "disk_wipe":            ("T1561",    "Impact"),
    "service_stop":         ("T1489",    "Impact"),
}

# ── Attack archetypes: multi-stage kill-chain sequences ─────────────────────
ARCHETYPES = {
    "credential_phishing": {
        "sequences": [
            ["phishing_email", "url_visit", "suspicious_login", "credential_login", "network_scan", "lateral_rdp"],
            ["spear_phishing", "url_visit", "credential_login", "system_enum", "lateral_smb"],
            ["phishing_email", "attachment_download", "credential_login", "suspicious_login", "lateral_wmi"],
        ],
        "next_stage": "Lateral Movement",
    },
    "malware_delivery": {
        "sequences": [
            ["phishing_email", "attachment_download", "macro_execution", "powershell", "scheduled_task", "dns_beacon"],
            ["spear_phishing", "attachment_download", "script_execution", "registry_run_key", "http_c2"],
            ["drive_by", "script_execution", "powershell", "startup_folder", "icmp_tunnel"],
        ],
        "next_stage": "Command & Control",
    },
    "ransomware": {
        "sequences": [
            ["phishing_email", "powershell", "privilege_escalation", "process_injection", "lateral_rdp", "ransomware_encrypt"],
            ["drive_by", "script_execution", "uac_bypass", "log_clearing", "lateral_smb", "ransomware_encrypt"],
            ["spear_phishing", "macro_execution", "token_impersonation", "masquerading", "lateral_wmi", "disk_wipe"],
        ],
        "next_stage": "Impact",
    },
    "data_theft": {
        "sequences": [
            ["phishing_email", "credential_login", "network_scan", "data_staged", "exfil_https"],
            ["spear_phishing", "mimikatz", "system_enum", "screen_capture", "exfil_ftp"],
            ["drive_by", "kerberoasting", "file_search", "keylogger", "dns_exfil"],
        ],
        "next_stage": "Exfiltration",
    },
    "apt_full_chain": {
        "sequences": [
            ["spear_phishing", "url_visit", "powershell", "process_injection", "scheduled_task", "dns_beacon",
             "privilege_escalation", "network_scan", "lateral_rdp", "data_staged", "exfil_https", "service_stop"],
            ["phishing_email", "attachment_download", "macro_execution", "log_clearing", "http_c2",
             "uac_bypass", "system_enum", "lateral_smb", "keylogger", "exfil_ftp", "disk_wipe"],
        ],
        "next_stage": "Exfiltration",
    },
    "insider_threat": {
        "sequences": [
            ["suspicious_login", "system_enum", "masquerading", "data_staged", "exfil_ftp"],
            ["credential_login", "file_search", "process_injection", "screen_capture", "dns_exfil"],
        ],
        "next_stage": "Exfiltration",
    },
}

def random_ip():
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_domain():
    tlds = ["com", "net", "org", "io"]
    words = ["secure", "login", "update", "cdn", "api", "auth", "verify",
             "access", "portal", "data", "sync", "cloud", "app"]
    return f"{random.choice(words)}-{random.randint(100,999)}.{random.choice(tlds)}"

def random_user(org_size=30):
    first = ["alice", "bob", "charlie", "diana", "evan", "fiona", "george",
             "helen", "ivan", "julia", "karl", "linda", "mike", "nancy",
             "oscar", "paula", "quinn", "rosa", "sam", "tina"]
    return f"{random.choice(first)}{random.randint(1, org_size):02d}"

def generate_campaign(campaign_num: int, archetype_name: str, archetype: dict) -> list[dict]:
    """Generate a single campaign as a list of event rows."""
    sequence = random.choice(archetype["sequences"])
    next_stage = archetype["next_stage"]

    # Randomise persona
    user = random_user()
    src_ip = random_ip()
    domain = random_domain()
    severity_base = random.randint(40, 70)

    # Start time: random day offset, random hour 06:00–22:00
    day_offset = random.randint(0, 364)
    hour_start = random.randint(6, 21)
    minute_start = random.randint(0, 59)
    base_time = datetime(2026, 1, 1, hour_start, minute_start) + timedelta(days=day_offset)

    events = []
    current_time = base_time

    for idx, event_type in enumerate(sequence):
        technique, stage = TECHNIQUE_MAP.get(event_type, ("T9999", "Unknown"))

        # Temporal variation: quick attacker (1–5 min) or slow APT (30–480 min)
        is_apt = archetype_name == "apt_full_chain"
        if is_apt:
            delta_minutes = random.randint(15, 120)
        else:
            delta_minutes = random.randint(1, 20)

        if idx == 0:
            delta_minutes = 0

        current_time += timedelta(minutes=delta_minutes)

        # Severity escalates as attack progresses
        severity = min(severity_base + (idx * random.randint(3, 8)), 100)

        # Some events come from pivoted hosts
        if idx > 2 and random.random() < 0.35:
            src_ip = random_ip()

        campaign_id = f"CAM-{campaign_num:04d}"
        event_id    = f"EVT-{campaign_num:04d}-{idx+1:02d}"

        events.append({
            "campaign_id":       campaign_id,
            "event_id":          event_id,
            "timestamp":         current_time.strftime("%Y-%m-%dT%H:%M:%S"),
            "user":              user,
            "source_ip":         src_ip,
            "domain":            domain,
            "event_type":        event_type,
            "mitre_technique":   technique,
            "mitre_stage":       stage,
            "severity":          severity,
            "time_delta_minutes": delta_minutes,
            "campaign_type":     archetype_name,
            "next_stage_label":  next_stage,
        })

    return events


def generate_dataset(n_campaigns: int = 600):
    """Generate n_campaigns total, distributed across archetypes."""
    all_rows = []
    archetype_names = list(ARCHETYPES.keys())

    for i in range(1, n_campaigns + 1):
        archetype_name = archetype_names[(i - 1) % len(archetype_names)]
        archetype = ARCHETYPES[archetype_name]
        rows = generate_campaign(i, archetype_name, archetype)
        all_rows.extend(rows)

    return all_rows


def write_csv(rows: list[dict], filepath: str):
    if not rows:
        return
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Written {len(rows)} event rows -> {filepath}")


def generate_transition_dataset(event_rows: list[dict]) -> list[dict]:
    """
    Extracts longitudinal stage-transition samples from raw campaign events.

    For a campaign with events E_1, E_2, ..., E_K:
    - Target: stage of next transition event E_{k+1}
    - Observed prefix: E_1 ... E_k (events prior to transition)
    - Input Features: Extracted ONLY from observed prefix E_1 ... E_k (Zero future leakage)
    """
    sys_path_added = False
    try:
        sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "backend")))
        sys_path_added = True
        from app.intelligence.feature_extractor import extract_features
    except Exception as e:
        print(f"Warning: could not import feature_extractor: {e}")
        return []

    campaigns = defaultdict(list)
    for r in event_rows:
        campaigns[r["campaign_id"]].append(r)

    transition_rows = []
    for cid, evs in campaigns.items():
        sorted_evs = sorted(evs, key=lambda x: x["timestamp"])
        seen_stages = []
        for k in range(len(sorted_evs)):
            curr_ev = sorted_evs[k]
            stage = curr_ev.get("mitre_stage", "").strip()

            if stage and stage != "Unknown" and stage not in seen_stages:
                if seen_stages:
                    # We have a stage transition boundary!
                    # Observed events: all events up to k-1
                    obs = sorted_evs[:k]
                    target_stage = stage

                    feats = extract_features(obs)
                    if feats:
                        row = {
                            "campaign_id": cid,
                            "prefix_length": len(obs),
                            "current_stage": obs[-1].get("mitre_stage", "").strip(),
                            "next_stage": target_stage,
                        }
                        row.update(feats)
                        transition_rows.append(row)

                seen_stages.append(stage)

    return transition_rows



def main():
    print("=== CAIP Dataset Generator ===")
    print(f"\nGenerating 600 campaigns across {len(ARCHETYPES)} archetypes...")

    all_rows = generate_dataset(600)

    # Campaign-level split: 80% train (480 campaigns), 20% val (120 campaigns)
    campaign_ids = sorted({r["campaign_id"] for r in all_rows})
    random.seed(42)
    random.shuffle(campaign_ids)
    split_idx   = int(len(campaign_ids) * 0.8)
    train_ids   = set(campaign_ids[:split_idx])
    val_ids     = set(campaign_ids[split_idx:])

    train_rows = [r for r in all_rows if r["campaign_id"] in train_ids]
    val_rows   = [r for r in all_rows if r["campaign_id"] in val_ids]

    base = os.path.dirname(os.path.abspath(__file__))

    # 1. Write raw campaign event logs
    write_csv(train_rows, os.path.join(base, "caip_attack_dataset.csv"))
    write_csv(val_rows,   os.path.join(base, "caip_validation_set.csv"))

    # 2. Write longitudinal transition samples (Zero leakage)
    train_trans = generate_transition_dataset(train_rows)
    val_trans   = generate_transition_dataset(val_rows)

    write_csv(train_trans, os.path.join(base, "caip_transition_dataset.csv"))
    write_csv(val_trans,   os.path.join(base, "caip_transition_validation.csv"))

    print(f"\n  Train campaigns : {len(train_ids)} ({len(train_trans)} transition samples)")
    print(f"  Val campaigns   : {len(val_ids)} ({len(val_trans)} transition samples)")
    print(f"  Total raw events: {len(all_rows)}")
    print("\n=== Dataset generation complete ===")


if __name__ == "__main__":
    main()
