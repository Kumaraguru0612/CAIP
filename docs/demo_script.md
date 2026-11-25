# CAIP Demonstration Script — Killer Demo Scenario: Credential Theft

**Target Audience**: Academic Evaluators, Guide, IEEE Reviewers, SOC Lead  
**Scenario Name**: Multi-Stage Credential Theft & Execution  
**Duration**: ~3-5 minutes  

---

## Scenario Overview & Objective

This demonstration illustrates how CAIP transforms fragmented, high-volume security telemetry into a unified, predictive attack campaign. Traditional SIEMs create separate alerts for individual suspicious logs, placing the burden of correlation on human analysts. CAIP automatically connects related events via a multi-signal context graph, calculates campaign-level risk, predicts subsequent attack stages, and selectively activates a safe Digital Twin to calculate blast radius and recommend responses.

---

## Timeline & Step-by-Step Execution

### Step 1: 10:00:01 — Suspicious URL Ingestion
- **Event**: EDR/Web Filter detects user `alice` navigating to a newly registered domain `http://phish-secure-login.xyz`.
- **SIEM Baseline**: Emits Alert #1 (`Suspicious URL Detected`). Score: Low.
- **CAIP Reaction**:
  - Event normalized: `Initial Access` (MITRE T1566 / T1204).
  - Campaign #1 Created (`Credential Theft & Execution`).
  - **Alerts Count**: 1 | **Campaign Risk**: 35 (Low/Medium).

---

### Step 2: 10:00:05 — Web Interaction & Payload Delivery
- **Event**: Browser process spawns user action downloading an obfuscated payload onto workstation `WORKSTATION-01` (`192.168.1.105`).
- **SIEM Baseline**: Emits Alert #2 (`User Visited Malicious URL`).
- **CAIP Reaction**:
  - Graph correlation matches entity context (`User: alice`, `Host: WORKSTATION-01`).
  - Correlation logic links Event #2 to Campaign #1.
  - **Alerts Count**: 2 | **Campaign Risk**: 55 (Medium).

---

### Step 3: 10:00:15 — Execution via Obfuscated PowerShell
- **Event**: Process monitoring records `powershell.exe -Enc QmFzaDY0IEVuY29kZWQ...` executed under user `alice`.
- **SIEM Baseline**: Emits Alert #3 (`Suspicious PowerShell Execution`).
- **CAIP Reaction**:
  - Event normalized: `Execution` (MITRE T1059.001).
  - Context graph links parent process ID and user session.
  - **Alerts Count**: 3 | **Campaign Risk**: 78 (High).

---

### Step 4: 10:00:25 — Credential Access Attempt
- **Event**: Mimikatz LSASS memory dumping attempt / LSASS handle access detected.
- **SIEM Baseline**: Emits Alert #4 (`Credential Access Detected`).
- **CAIP Reaction**:
  - Event normalized: `Credential Access` (MITRE T1003).
  - Risk engine crosses critical threshold (**Risk > 80**).
  - **Alerts Count**: 4 | **Campaign Risk**: 92 (Critical).
  - **Attack Predictor Activated**:
    - **Lateral Movement**: **82%**
    - **Exfiltration**: **67%**
    - **Impact (Ransomware)**: **41%**
  - **Cost-Aware Router Decision**: Risk score 92 > Threshold 80 → **Route to Digital Twin Sandbox**.

---

### Step 5: 10:00:40 — Command & Control Communication + Digital Twin Blast Radius
- **Event**: Workstation initiates DNS beaconing to `c2-control.attacker.net`.
- **SIEM Baseline**: Emits Alert #5 (`Suspicious DNS Communication`). SOC analyst has 5 un-correlated alerts in queue.
- **CAIP Reaction**:
  - **DIGITAL TWIN ACTIVATED** (Safe sandboxed behavior emulation).
  - **Observed + Predicted Behavior Combined**:
    - Simulated Process: `mimikatz.exe`, `powershell.exe`
    - Simulated Network: Connection to `c2-control.attacker.net`
    - Simulated Files: `C:\Users\alice\AppData\Local\Temp\dump.dmp`
  - **Calculated Blast Radius**:
    - **Users**: 1 (`alice`)
    - **Devices**: 1 (`WORKSTATION-01`)
    - **Domains**: 2 (`phish-secure-login.xyz`, `c2-control.attacker.net`)
    - **IP Addresses**: 1 (`192.168.1.105`)
  - **Automated Response Playbook**:
    1. **Immediate**: Force password reset & revoke active tokens for user `alice`.
    2. **Network**: Block domains `phish-secure-login.xyz` and `c2-control.attacker.net` on perimeter firewall.
    3. **Host Isolation**: Quarantine host `WORKSTATION-01` (`192.168.1.105`).
    4. **Credential Audit**: Perform domain-wide Kerberos ticket audit.

---

## Visual Comparison Showcase (Centerpiece)

```
TRADITIONAL SIEM VIEW (5 Unrelated Alerts)
Alert 1: Suspicious URL ───► Analyst Queue
Alert 2: PowerShell ───────► Analyst Queue
Alert 3: Credential Login ─► Analyst Queue
Alert 4: DNS Beacon ───────► Analyst Queue
Alert 5: Network Traffic ──► Analyst Queue
(Analyst must manually connect dots across 500 daily alerts)

VS

CAIP CAMPAIGN VIEW (1 Correlated Campaign)
                   ┌── 10:00:01 Suspicious URL
                   ├── 10:00:05 User Interaction
ATTACK CAMPAIGN ───┼── 10:00:15 PowerShell Exec
(Risk: 92/100)     ├── 10:00:25 Credential Access
                   └── 10:00:40 DNS C2 Beacon
(CAIP connects events into 1 actionable story with automatic blast radius & containment)
```
