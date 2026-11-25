import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import os

def draw_architecture():
    fig, ax = plt.subplots(figsize=(12, 14), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')
    fig.patch.set_facecolor('#0f172a')
    ax.set_facecolor('#0f172a')

    # Title
    ax.text(50, 96, "CAIP SYSTEM ARCHITECTURE", fontsize=18, fontweight='bold', color='#f8fafc', ha='center')
    ax.text(50, 93.5, "Context-Aware Attack Correlation & Predictive Digital Twin Defense", fontsize=10, color='#94a3b8', ha='center')

    boxes = [
        ("SECURITY TELEMETRY SOURCES\n(EDR, SIEM, Network, Firewall, Web Filters)", 50, 87, 80, 5, "#1e293b", "#38bdf8"),
        ("INGESTION & SCHEMA NORMALIZATION\n(Standardized JSON Event Representation)", 50, 78, 80, 5, "#1e293b", "#38bdf8"),
        ("CONTEXT GRAPH ENGINE (Neo4j)\n(User, Host, IP, Process Entity Relationships)", 50, 69, 80, 5, "#1e293b", "#818cf8"),
        ("MULTI-SIGNAL CAMPAIGN CORRELATION ENGINE\n(Temporal Window + Identity Co-occurrence)", 50, 60, 80, 5, "#1e293b", "#c084fc"),
        ("CAMPAIGN RISK ENGINE\n(Dynamic Kill-Chain Stage Escalation Scoring)", 50, 51, 80, 5, "#1e293b", "#f43f5e"),
        ("ATTACK STAGE PREDICTOR (XGBoost + SHAP)\n(Transition Probabilities & Local Feature Attribution)", 50, 42, 80, 5, "#1e293b", "#fbbf24"),
        ("COST-AWARE ROUTING ENGINE\n(Evaluates Risk Score R against Computational Thresholds)", 50, 33, 80, 5, "#1e293b", "#34d399"),
    ]

    for label, x, y, w, h, bg, border in boxes:
        rect = patches.FancyBboxPatch((x - w/2, y - h/2), w, h, boxstyle="round,pad=0.5", ec=border, fc=bg, lw=2)
        ax.add_patch(rect)
        ax.text(x, y, label, fontsize=10, fontweight='bold', color='#f8fafc', ha='center', va='center')

    # Routing split boxes
    routes = [
        ("LOW RISK (R < 40)\nMonitor / Log", 20, 21, 26, 5, "#1e293b", "#64748b"),
        ("MEDIUM RISK (40 ≤ R < 80)\nAnalyst Queue", 50, 21, 26, 5, "#1e293b", "#fbbf24"),
        ("HIGH RISK (R ≥ 80)\nDIGITAL TWIN", 80, 21, 26, 5, "#1e293b", "#f43f5e"),
    ]
    for label, x, y, w, h, bg, border in routes:
        rect = patches.FancyBboxPatch((x - w/2, y - h/2), w, h, boxstyle="round,pad=0.5", ec=border, fc=bg, lw=2)
        ax.add_patch(rect)
        ax.text(x, y, label, fontsize=9, fontweight='bold', color='#f8fafc', ha='center', va='center')

    # Blast radius & Playbook
    twin_sub = [
        ("BLAST RADIUS & CONTAINMENT PLAYBOOK\n(Identity Revocation, Firewall Domain Block, Host Quarantine)", 80, 10, 34, 6, "#1e293b", "#a855f7")
    ]
    for label, x, y, w, h, bg, border in twin_sub:
        rect = patches.FancyBboxPatch((x - w/2, y - h/2), w, h, boxstyle="round,pad=0.5", ec=border, fc=bg, lw=2)
        ax.add_patch(rect)
        ax.text(x, y, label, fontsize=8.5, fontweight='bold', color='#f8fafc', ha='center', va='center')

    # SOC Dashboard bottom bar
    rect_soc = patches.FancyBboxPatch((10, 1), 80, 4.5, boxstyle="round,pad=0.3", ec="#38bdf8", fc="#0284c7", lw=2)
    ax.add_patch(rect_soc)
    ax.text(50, 3.25, "UNIFIED SOC DASHBOARD & ACTIONABLE PLAYBOOKS", fontsize=11, fontweight='bold', color='#ffffff', ha='center', va='center')

    # Arrows
    for y in [84.5, 75.5, 66.5, 57.5, 48.5, 39.5]:
        ax.annotate('', xy=(50, y-2.5), xytext=(50, y), arrowprops=dict(arrowstyle="->", color="#94a3b8", lw=2.5))

    # Routing arrows from Cost Router
    ax.annotate('', xy=(20, 23.5), xytext=(40, 30.5), arrowprops=dict(arrowstyle="->", color="#64748b", lw=2))
    ax.annotate('', xy=(50, 23.5), xytext=(50, 30.5), arrowprops=dict(arrowstyle="->", color="#fbbf24", lw=2))
    ax.annotate('', xy=(80, 23.5), xytext=(60, 30.5), arrowprops=dict(arrowstyle="->", color="#f43f5e", lw=2))

    # Arrow from Twin to Blast Radius
    ax.annotate('', xy=(80, 13), xytext=(80, 18.5), arrowprops=dict(arrowstyle="->", color="#a855f7", lw=2))

    plt.tight_layout()
    out_path = os.path.join(os.path.dirname(__file__), "architecture.png")
    plt.savefig(out_path, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"Architecture diagram saved to {out_path}")

def draw_workflow():
    fig, ax = plt.subplots(figsize=(12, 10), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')
    fig.patch.set_facecolor('#0f172a')
    ax.set_facecolor('#0f172a')

    ax.text(50, 95, "CREDENTIAL THEFT ATTACK SIMULATION WORKFLOW", fontsize=16, fontweight='bold', color='#f8fafc', ha='center')
    ax.text(50, 92, "Sequential Multi-Stage Event Correlation & Live Risk Escalation", fontsize=10, color='#94a3b8', ha='center')

    steps = [
        ("10:00:01 — Suspicious URL Detected", "Initial Access | Risk: 35 | Alerts: 1", 50, 83, "#38bdf8"),
        ("10:00:05 — User Interaction & Payload Download", "Execution Prep | Risk: 55 | Alerts: 2", 50, 70, "#818cf8"),
        ("10:00:15 — Obfuscated PowerShell Execution", "Execution | Risk: 78 | Alerts: 3", 50, 57, "#fbbf24"),
        ("10:00:25 — Credential Access Attempt (Mimikatz)", "Credential Access | Risk: 92 | Alerts: 4", 50, 44, "#f43f5e"),
        ("10:00:40 — C2 Beaconing & Digital Twin Triggered", "Command & Control | Risk: 95 | Twin Active", 50, 31, "#a855f7"),
    ]

    for title, desc, x, y, border in steps:
        rect = patches.FancyBboxPatch((x - 35, y - 4), 70, 8, boxstyle="round,pad=0.5", ec=border, fc="#1e293b", lw=2)
        ax.add_patch(rect)
        ax.text(x, y + 1.5, title, fontsize=11, fontweight='bold', color='#f8fafc', ha='center', va='center')
        ax.text(x, y - 1.5, desc, fontsize=9.5, color='#94a3b8', ha='center', va='center')

    for y in [79, 66, 53, 40]:
        ax.annotate('', xy=(50, y-5), xytext=(50, y), arrowprops=dict(arrowstyle="->", color="#38bdf8", lw=2.5))

    # Bottom decision summary box
    rect_sum = patches.FancyBboxPatch((15, 5), 70, 14, boxstyle="round,pad=0.5", ec="#34d399", fc="#064e3b", lw=2)
    ax.add_patch(rect_sum)
    ax.text(50, 15, "PREDICTED OUTCOME & BLAST RADIUS", fontsize=11, fontweight='bold', color='#34d399', ha='center')
    ax.text(50, 11, "Lateral Movement (82%) | Exfiltration (67%) | Ransomware Impact (41%)", fontsize=9.5, color='#f8fafc', ha='center')
    ax.text(50, 7.5, "Blast Radius: 1 User, 1 Device, 2 Domains, 1 IP | Response: Contain & Reset Credentials", fontsize=9, color='#e2e8f0', ha='center')

    plt.tight_layout()
    out_path = os.path.join(os.path.dirname(__file__), "workflow.png")
    plt.savefig(out_path, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"Workflow diagram saved to {out_path}")

if __name__ == "__main__":
    draw_architecture()
    draw_workflow()
