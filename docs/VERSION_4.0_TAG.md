# CAIP v4.0 Architecture Freeze & Backup Manifest

**Release Version**: 4.0.0-FREEZE  
**Freeze Date**: August 14, 2026  
**Status**: Stable Demonstration & Research Benchmark Release  

---

## 1. System Inventory

| Module | Location | Purpose |
|---|---|---|
| Ingestion & Normalization | [`backend/app/ingestion/`](../backend/app/ingestion/) | Schema normalization, EDR/SIEM log ingestion |
| Context Graph | [`backend/app/graph/`](../backend/app/graph/) | Network/Entity graph modeling (User, Host, IP, Process) |
| Intelligence & Correlation | [`backend/app/intelligence/`](../backend/app/intelligence/) | Multi-signal campaign engine, XGBoost attack prediction, Risk engine, Digital Twin, Cost-aware router |
| XAI Explainer | [`backend/app/xai/`](../backend/app/xai/) | SHAP feature importance & risk contribution explanations |
| Synthetic & Adapter Datasets | [`datasets/`](../datasets/) | `caip_attack_dataset.csv`, `caip_validation_set.csv`, `cicids_adapter.py` (CICIDS2017-derived benchmark adapter) |
| IEEE Experiment Suite | [`experiments/`](../experiments/) | Experiments 1–7 (Baseline, Ablation, Correlation, Prediction, Twin, Cost Routing, Unseen Generalization) |
| Frontend Dashboard | [`frontend/src/App.jsx`](../frontend/src/App.jsx) | React + Tailwind + Lucide SOC dashboard & Live Simulation Panel |

---

## 2. Core Architecture Rules During Freeze

1. **Backend Endpoint Contract**:
   - `/api/v1/events/ingest` & `/api/v1/events/ingest/batch` must accept normalized schemas.
   - `/api/v1/campaigns` & `/api/v1/campaigns/{id}` remain backward compatible.
   - `/api/v1/simulation/credential-theft/*` serves live demonstration state updates.
2. **Digital Twin Execution Safety**:
   - Twin simulation runs in non-destructive sandbox mode. No real execution of malicious payloads.
3. **Research Disclaimers**:
   - All experimental reports must state:
     > *"The evaluation demonstrates the feasibility of the proposed architecture under controlled benchmark conditions. The synthetic benchmark results should not be interpreted as real-world zero-day detection performance."*
   - CICIDS2017 dataset interactions must be designated as **"CICIDS2017-derived benchmark adapter"**.
