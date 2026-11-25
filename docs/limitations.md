# CAIP Research Limitations & Disclaimers

**Document Version**: 4.0  
**Target Scope**: Academic Evaluation & IEEE Paper Section 12  

---

## 1. Controlled Synthetic Benchmark Disclaimer

> [!WARNING]  
> **Synthetic Benchmark Evaluation Disclaimer**:  
> *"The evaluation demonstrates the feasibility of the proposed architecture under controlled benchmark conditions. The synthetic benchmark results should not be interpreted as real-world zero-day detection performance."*

### Context & Justification
- Synthetic datasets (`caip_attack_dataset.csv`, `caip_validation_set.csv`) generated for evaluation provide structured ground-truth attack chains designed to test campaign correlation algorithms and predictive routing logic.
- High accuracy metrics (e.g., high prediction accuracy and F1 scores) on synthetic benchmarks reflect the system's ability to model known sequential transition dynamics under clean labeling conditions.
- Real-world enterprise network environments introduce telemetry noise, missing event logs, clock drift, non-standard user behaviors, and unseen attack vectors. Performance in live enterprise deployments may vary.

---

## 2. Dataset Nomenclature & CICIDS2017 Framing

> [!IMPORTANT]  
> **CICIDS2017 Dataset Adapter Scope**:  
> Evaluating CAIP on benchmark network traffic datasets uses a **"CICIDS2017-derived benchmark adapter"**.

### Technical Clarification for Peer Reviewers
- CAIP does not process the raw 50+ GB PCAP files of the original Canadian Institute for Cybersecurity (CIC) 2017 dataset directly in real-time.
- Instead, the adapter parses and transforms published feature distributions and event mappings derived from the CICIDS2017 benchmark into standardized CAIP event representations.
- This mapping ensures consistent schema integration while evaluating correlation fidelity across network-level attack sequences.

---

## 3. Scope of Digital Twin Emulation

- The current Digital Twin implementation operates as a **non-destructive behavior sandbox emulator**.
- It simulates file system mutations, registry changes, process hierarchy spawns, and network connections based on MITRE ATT&CK technique parameters.
- It does not execute live malicious binary payloads or kernel-level exploits on host machines, ensuring complete safety during evaluation and operational demonstrations.

---

## 4. Scalability Boundaries & Future Work

- **Context Graph Limits**: Neo4j context graph queries perform in sub-50ms for graph clusters up to 100,000 nodes. Ultra-large enterprise graphs (>10,000,000 entities) require distributed graph database clustering or partition strategies.
- **Machine Learning Models**: The attack prediction engine relies on XGBoost trained on discrete MITRE ATT&CK stage transitions. Future work involves adopting Graph Neural Networks (GNNs) and Transformer-based temporal models for continuous log stream modeling.
