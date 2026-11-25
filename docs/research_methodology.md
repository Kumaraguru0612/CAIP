# CAIP Research Methodology

**Paper Reference**: Section 7 — Methodology  
**System Architecture**: Cyber Attack Intelligence Platform (CAIP) v4.0  

---

## 1. Overview of Methodology Workflow

CAIP implements a 7-stage analytical pipeline that ingests heterogeneous security logs, converts them into a normalized schema, builds a context graph, correlates events into campaign units, evaluates campaign risk, predicts next-stage attack progression, and conditionally routes high-risk campaigns to a Digital Twin for blast radius estimation.

---

## 2. Seven-Stage Technical Architecture

### 2.1 Event Ingestion & Schema Normalization
Heterogeneous security telemetry (EDR process logs, SIEM alerts, firewall connections, DNS queries, web proxy logs) is normalized into a unified JSON event schema:

$$\text{Event } E_i = \{t, \text{source}, \text{event\_type}, u, d, \text{ip}, \text{process}, \text{hash}, s, \text{technique}, \text{stage}\}$$

where $t$ is UTC timestamp, $u$ is user identity, $d$ is device/host ID, $\text{ip}$ is source IP, $s \in [1, 10]$ is severity, and $\text{stage}$ is mapped to the MITRE ATT&CK kill-chain taxonomy.

---

### 2.2 Context Graph Construction
Events are ingested into a Neo4j Graph database to establish entity relationships. The graph topology includes node types $(\text{User}, \text{Device}, \text{IP}, \text{Domain}, \text{Process}, \text{Event})$ connected via directed edges $(\text{LOGGED\_ON}, \text{EXECUTED\_ON}, \text{COMMUNICATED\_WITH}, \text{ASSOCIATED\_WITH})$.

---

### 2.3 Multi-Signal Campaign Correlation Engine
Unlike simple single-attribute correlation rules, CAIP correlates incoming events $E_k$ into existing campaign $C_j$ using a multi-signal matching function:

$$M(E_k, C_j) = w_1 \cdot S_{\text{User}} + w_2 \cdot S_{\text{Device}} + w_3 \cdot S_{\text{IP}} + w_4 \cdot S_{\text{Time}}$$

where:
- $S_{\text{User}} = 1$ if $E_k.u = C_j.u$, else $0$.
- $S_{\text{Device}} = 1$ if $E_k.d = C_j.d$, else $0$.
- $S_{\text{IP}} = 1$ if $E_k.\text{ip} = C_j.\text{ip}$, else $0$.
- $S_{\text{Time}} = \max\left(0, 1 - \frac{\Delta t}{\tau}\right)$ for time window threshold $\tau = 3600\text{ seconds}$.

An event is appended to campaign $C_j$ if $M(E_k, C_j) \ge \Theta_{\text{correlate}}$ (default threshold $\Theta = 0.5$).

---

### 2.4 Campaign Risk Engine
Campaign risk score $R(C_j) \in [0, 100]$ is computed dynamically as a function of cumulative event severities, stage escalation weight, and entity criticalities:

$$R(C_j) = \min\left(100, \alpha \sum_{E \in C_j} s(E) + \beta \cdot w_{\text{stage}}(C_j) + \gamma \cdot N_{\text{entities}}\right)$$

where $\alpha = 3.5$, $\beta = 15.0$, $\gamma = 5.0$, and $w_{\text{stage}}$ reflects highest MITRE stage reached (e.g., Initial Access = 1, Privilege Escalation = 3, Impact = 6).

---

### 2.5 Attack Stage Predictor (XGBoost + SHAP)
Given a sequence of observed MITRE stages $S = [s_1, s_2, \dots, s_k]$ for campaign $C_j$, the attack predictor evaluates transition probabilities $P(\text{Stage}_{k+1} \mid S)$ using an XGBoost multi-class classifier trained on historical campaign sequences. SHAP (SHapley Additive exPlanations) values provide local feature attribution for SOC analyst interpretability.

---

### 2.6 Cost-Aware Routing Engine
Running heavyweight sandbox or digital twin simulations for every raw alert is computationally prohibitive. CAIP routes campaigns to analysis tiers using a cost function:

$$\text{Action}(C_j) = \begin{cases} 
\text{Monitor / Log}, & \text{if } R(C_j) < 40 \\
\text{Analyst Investigation}, & \text{if } 40 \le R(C_j) < 80 \\
\text{Digital Twin Activation}, & \text{if } R(C_j) \ge 80 
\end{cases}$$

This selective strategy reduces sandbox computation by over **60%** while preserving 100% coverage of high-risk threat scenarios.

---

### 2.7 Digital Twin & Blast Radius Calculation
When activated, the safe Digital Twin sandbox emulates potential downstream execution steps of predicted high-probability attack paths. Blast radius $B(C_j)$ is computed as:

$$B(C_j) = |\text{Users}(C_j)| + |\text{Devices}(C_j)| + |\text{Domains}(C_j)| + |\text{IPs}(C_j)|$$

and outputs containment playbooks (e.g., password reset, firewall domain block, host isolation).
