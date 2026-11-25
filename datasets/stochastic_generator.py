"""
CAIP Stochastic Attack-Path Dataset Generator (Phase B)
========================================================
Produces realistic, stochastic multi-stage attack campaigns across MITRE ATT&CK
kill-chain paths. Enforces a strict HELD-OUT SEQUENCE TEMPLATE SPLIT where validation
campaign sequence structures are 100% unseen in training.

Output:
  datasets/caip_stochastic_attack_dataset.csv       — Raw train event logs
  datasets/caip_stochastic_validation_set.csv       — Raw validation event logs
  datasets/caip_stochastic_transition_dataset.csv   — Train transition samples
  datasets/caip_stochastic_transition_validation.csv — Validation transition samples
"""

import os
import sys
import csv
import random
from datetime import datetime, timedelta
from collections import defaultdict

random.seed(42)

# Import technique map from main dataset generator if available
try:
    from datasets.dataset_generator import TECHNIQUE_MAP, random_ip, random_domain, random_user
except ImportError:
    from dataset_generator import TECHNIQUE_MAP, random_ip, random_domain, random_user

# Group techniques by stage
STAGE_TECHNIQUES = defaultdict(list)
for tech, (code, stage) in TECHNIQUE_MAP.items():
    STAGE_TECHNIQUES[stage].append(tech)

# Stochastic MITRE ATT&CK stage transition graph
STAGE_GRAPH = {
    "Initial Access":        ["Execution", "Credential Access", "Discovery"],
    "Execution":             ["Persistence", "Privilege Escalation", "Defense Evasion", "Discovery"],
    "Persistence":           ["Privilege Escalation", "Command & Control", "Defense Evasion", "Discovery"],
    "Privilege Escalation":  ["Defense Evasion", "Lateral Movement", "Discovery", "Credential Access"],
    "Defense Evasion":       ["Lateral Movement", "Discovery", "Credential Access", "Command & Control"],
    "Credential Access":     ["Discovery", "Lateral Movement", "Privilege Escalation", "Collection"],
    "Discovery":             ["Lateral Movement", "Collection", "Credential Access", "Exfiltration"],
    "Lateral Movement":      ["Collection", "Impact", "Exfiltration", "Command & Control"],
    "Command & Control":      ["Lateral Movement", "Collection", "Exfiltration", "Impact"],
    "Collection":            ["Exfiltration", "Impact"],
    "Exfiltration":          ["Impact", "END"],
    "Impact":                ["END"],
}


def sample_stochastic_path() -> list[str]:
    """Sample a random valid path through the MITRE stage transition graph."""
    path = ["Initial Access"]
    max_length = random.randint(4, 9)

    curr = "Initial Access"
    while len(path) < max_length and curr in STAGE_GRAPH:
        next_options = STAGE_GRAPH[curr]
        next_stage = random.choice(next_options)
        if next_stage == "END":
            break
        path.append(next_stage)
        curr = next_stage

    return path


def generate_stochastic_campaign(campaign_num: int, path: list[str]) -> list[dict]:
    """Generate a single campaign event sequence from a given stage path."""
    user = random_user()
    src_ip = random_ip()
    domain = random_domain()
    severity_base = random.randint(35, 65)

    day_offset = random.randint(0, 364)
    hour_start = random.randint(6, 21)
    minute_start = random.randint(0, 59)
    base_time = datetime(2026, 1, 1, hour_start, minute_start) + timedelta(days=day_offset)

    events = []
    current_time = base_time
    event_idx = 1

    for stage_idx, stage in enumerate(path):
        # Sample 1 to 2 techniques for this stage
        techs_available = STAGE_TECHNIQUES.get(stage, ["powershell"])
        n_techs = random.choice([1, 1, 2]) if len(techs_available) > 1 else 1
        chosen_techs = random.sample(techs_available, min(n_techs, len(techs_available)))

        for tech in chosen_techs:
            mitre_code, mitre_stage = TECHNIQUE_MAP.get(tech, ("T9999", stage))
            delta_minutes = 0 if event_idx == 1 else random.randint(2, 45)
            current_time += timedelta(minutes=delta_minutes)

            severity = min(severity_base + (stage_idx * random.randint(4, 9)), 100)
            if stage_idx > 2 and random.random() < 0.30:
                src_ip = random_ip()

            campaign_id = f"STOCH-CAM-{campaign_num:04d}"
            event_id    = f"EVT-S{campaign_num:04d}-{event_idx:02d}"

            events.append({
                "campaign_id":       campaign_id,
                "event_id":          event_id,
                "timestamp":         current_time.strftime("%Y-%m-%dT%H:%M:%S"),
                "user":              user,
                "source_ip":         src_ip,
                "domain":            domain,
                "event_type":        tech,
                "mitre_technique":   mitre_code,
                "mitre_stage":       mitre_stage,
                "severity":          severity,
                "time_delta_minutes": delta_minutes,
                "campaign_type":     "stochastic_multi_stage",
                "next_stage_label":  path[-1],
            })
            event_idx += 1

    return events


def generate_transition_dataset(event_rows: list[dict]) -> list[dict]:
    """Extract longitudinal stage transition samples from raw event rows."""
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "backend")))
    from app.intelligence.feature_extractor import extract_features

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
    print("=== CAIP Stochastic Dataset Generator (Phase B) ===")
    random.seed(42)

    # 1. Generate 800 stochastic campaigns
    n_campaigns = 800
    campaign_records = []
    template_map = defaultdict(list)

    for i in range(1, n_campaigns + 1):
        path = sample_stochastic_path()
        seq_tuple = tuple(path)
        events = generate_stochastic_campaign(i, path)
        campaign_records.append((i, seq_tuple, events))
        template_map[seq_tuple].append((i, events))

    unique_templates = sorted(list(template_map.keys()))
    print(f"\nGenerated {n_campaigns} campaigns across {len(unique_templates)} unique sequence templates.")

    # 2. Strict Sequence Template Split (70% train templates, 30% val templates)
    random.shuffle(unique_templates)
    split_idx = int(len(unique_templates) * 0.70)
    train_templates = set(unique_templates[:split_idx])
    val_templates   = set(unique_templates[split_idx:])

    template_overlap = train_templates.intersection(val_templates)
    print(f"  Train templates : {len(train_templates)}")
    print(f"  Val templates   : {len(val_templates)} (100% HELD-OUT UNSEEN STRUCTURES)")
    print(f"  Template overlap: {len(template_overlap)}")

    train_rows = []
    val_rows = []
    train_cids = set()
    val_cids = set()

    for seq_tuple, items in template_map.items():
        if seq_tuple in train_templates:
            for cid_num, evs in items:
                train_rows.extend(evs)
                train_cids.add(evs[0]["campaign_id"])
        else:
            for cid_num, evs in items:
                val_rows.extend(evs)
                val_cids.add(evs[0]["campaign_id"])

    cid_overlap = train_cids.intersection(val_cids)
    print(f"  Train campaigns : {len(train_cids)}")
    print(f"  Val campaigns   : {len(val_cids)}")
    print(f"  Campaign overlap: {len(cid_overlap)}")

    # 3. Generate longitudinal transition datasets
    train_trans = generate_transition_dataset(train_rows)
    val_trans   = generate_transition_dataset(val_rows)

    base = os.path.dirname(os.path.abspath(__file__))

    def _write_csv(rows, filepath):
        if not rows:
            return
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Written {len(rows)} rows -> {filepath}")

    _write_csv(train_rows, os.path.join(base, "caip_stochastic_attack_dataset.csv"))
    _write_csv(val_rows,   os.path.join(base, "caip_stochastic_validation_set.csv"))
    _write_csv(train_trans, os.path.join(base, "caip_stochastic_transition_dataset.csv"))
    _write_csv(val_trans,   os.path.join(base, "caip_stochastic_transition_validation.csv"))

    print(f"\n  Train transition samples : {len(train_trans)}")
    print(f"  Val transition samples   : {len(val_trans)}")
    print("\n=== Phase B Dataset Generation Complete ===")


if __name__ == "__main__":
    main()
