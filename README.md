# CAIP — Collaborative Attack Intelligence Platform (v4.0)

CAIP is a full-stack cybersecurity intelligence and research platform designed to transform fragmented security alerts into correlated, explainable multi-stage attack campaigns. It combines heterogeneous telemetry normalization, Neo4j context-graph correlation, XGBoost next-stage attack prediction, SHAP explainability, cost-aware routing, and a non-destructive Digital Twin simulation engine with a real-time React SOC dashboard.

---

## Objectives

- **Reduce SOC Alert Fatigue**: Group disconnected EDR, SIEM, network, and Sysmon alerts into unified multi-stage campaigns using multi-signal entity and temporal correlation.
- **Predict Imminent Attack Stages**: Forecast likely next MITRE ATT&CK kill-chain stages from observed campaign prefixes using XGBoost.
- **Provide Transparent Explainability (XAI)**: Surface rule-level detection reasons, correlation rationales, and SHAP feature attributions for analyst trust.
- **Optimize Simulation Compute**: Use cost-aware routing to selectively trigger Digital Twin blast-radius emulation only for high-risk campaigns ($R \ge 80$).
- **Streamline SOC Operations**: Unify threat intelligence enrichment, incident management, case evidence/notes, and automated response playbooks in a single interface.

---

## Key Features

- **Log Ingestion & Normalization**: Validates and maps heterogeneous security events onto MITRE ATT&CK techniques and stages (`backend/app/ingestion/`).
- **Live Windows Sysmon Integration**: Streams `Microsoft-Windows-Sysmon/Operational` events in real time via the Sysmon collector (`agent/sysmon_collector.py`, `sysmon_service.py`).
- **Context Graph Modeling**: Builds User, Host/Device, IP, Domain, and Process entity relationships in Neo4j (`backend/app/graph/`).
- **Multi-Signal Campaign Correlation & Risk Engine**: Clusters related alerts into campaigns and computes dynamic severity/risk scores (`campaign_engine.py`, `risk_engine.py`).
- **Next-Stage Attack Predictor & XAI**: Forecasts upcoming attack stages with XGBoost and explains risk drivers with SHAP (`attack_predictor.py`, `xai/explainer.py`).
- **Cost-Aware Router & Safe Digital Twin**: Routes high-risk campaigns to a non-destructive sandbox to estimate blast radius and containment impact (`cost_router.py`, `digital_twin.py`).
- **SOC Operations & Threat Intelligence**: Includes campaign similarity matching, indicator reputation tracking, incident lifecycle workflows, notifications, and response playbooks.
- **Unified SOC Dashboard & Simulator**: React + Tailwind CSS dashboard (`frontend/`), interactive 5-step simulator (`caip-simulator/`), and safe demo scenarios (`demo/`).
- **Research & Benchmark Suite**: Reproducible evaluation scripts (`experiments/exp1_*` through `exp7_*`), datasets (`datasets/`), and frozen benchmark artifacts (`experiments/results/`).

---

## Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend API** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy |
| **Databases** | PostgreSQL (with automatic local SQLite fallback), Neo4j |
| **ML & XAI** | XGBoost, SHAP (`TreeExplainer`), scikit-learn, pandas, NumPy |
| **Frontend UI** | React 19, Vite 8, Tailwind CSS, Lucide React |
| **Telemetry & Ops** | Windows Event Log / Sysmon (`pywin32`), Docker & Docker Compose |
| **Testing** | `pytest`, FastAPI `TestClient`, standalone verification scripts |

---

## Project Structure

```text
CAIP/
├── agent/                  # Standalone Windows Sysmon collector agent
├── backend/
│   ├── app/
│   │   ├── config.py       # Pydantic settings & environment configuration
│   │   ├── main.py         # FastAPI entrypoint & unified static serving
│   │   ├── database/       # SQLAlchemy engine (Postgres + SQLite fallback) & models
│   │   ├── graph/          # Neo4j context graph builder & Cypher queries
│   │   ├── ingestion/      # Event collector, normalizer, Sysmon live stream
│   │   ├── intelligence/   # Correlation, risk, XGBoost predictor, Twin, SOC engines
│   │   └── xai/            # SHAP explainability module
│   ├── Dockerfile
│   ├── requirements.txt
│   └── verify_backend.py   # Standalone end-to-end verification pipeline
├── caip-simulator/         # 5-step interactive live attack simulator UI
├── datasets/               # Synthetic datasets & CICIDS2017-derived benchmark adapter
├── demo/                   # Safe cybersecurity demonstration assets
├── docs/                   # Architecture diagrams, IEEE paper draft, results & tags
├── experiments/            # Experiments 1–7 & frozen JSON/graph result artifacts
├── frontend/               # React + Vite + Tailwind CSS SOC dashboard
├── research/               # Scientific audit & frozen results summary
├── tests/                  # Pytest unit & integration test suite
├── docker-compose.yml      # PostgreSQL, Neo4j, FastAPI, and Vite orchestration
├── .env.example            # Safe environment variable template (copy to .env)
├── package.json            # Root npm convenience scripts
├── pyproject.toml          # Pytest & Python path configuration
├── run.py                  # Single-command unified launcher
└── start.bat               # Portable Windows quick-start launcher
```

---

## Installation & Execution

### Prerequisites

- **Python 3.10+**
- **Node.js 18+ & npm** (for building/running the React frontend)
- **Docker Desktop** *(optional, required only for Option 2 with PostgreSQL + Neo4j)*

### 1. Install Dependencies

**Backend (Python):**
```bash
cd backend
pip install -r requirements.txt
cd ..
```

*(Optional)* Create and activate a virtual environment before installing:
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

**Optional Windows-Only Dependencies (Live Sysmon Telemetry):**
The standalone Windows Sysmon collector (`agent/sysmon_collector.py`, `sysmon_collector.py`) and live host event streaming require:
- **Windows OS** with **Microsoft Sysmon** installed and running (`Microsoft-Windows-Sysmon/Operational` channel)
- **`pywin32`** (`pip install pywin32`) — intentionally omitted from `backend/requirements.txt` so Linux/Docker deployments remain cross-platform
- *(Optional)* Run `enable_sysmon_reader.bat` as Administrator if standard user processes need read permissions on the Sysmon event channel

**Frontend (Node.js):**
```bash
cd frontend
npm install
cd ..
```

### 2. Environment Configuration

Copy the safe template to `.env` when using Docker Compose or external PostgreSQL/Neo4j instances (never commit `.env` to Git):

```bash
# Windows (PowerShell / CMD):
copy .env.example .env
# Linux/macOS:
cp .env.example .env
```

Edit `.env` with your own local credentials:
```env
ENVIRONMENT=development
CAIP_PORT=8000

POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_postgres_password_here
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=caip
DATABASE_URL=postgresql://postgres:your_postgres_password_here@localhost:5432/caip

NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password_here
```

> **Local Development Fallback**: If `DATABASE_URL` and `POSTGRES_PASSWORD` are left unset (or PostgreSQL is unreachable on `localhost:5432`), CAIP automatically falls back to local SQLite (`backend/caip_local.db`), and Neo4j graph syncing is skipped gracefully when Neo4j is not running. Option 1 (`python run.py` / `start.bat`) therefore works out of the box without requiring `.env` credentials.

---

### Option 1: Single-Command Local Run (No Docker Required)

From the project root, run:
```bash
python run.py
```
Or use:
- `npm start`
- `.\start.bat` (Windows — auto-detects `venv`, `.venv`, `backend\venv`, or system Python)

This builds `frontend/dist` if missing, starts the unified FastAPI + static frontend server, and opens your browser:
- **SOC Dashboard**: `http://localhost:8000/`
- **Interactive API Docs (Swagger)**: `http://localhost:8000/docs`
- **5-Step Live Demo Simulator**: `http://localhost:8000/simulator`

### Option 2: Full Stack with Docker Compose (PostgreSQL + Neo4j)

Ensure `.env` exists (copied from `.env.example` with `POSTGRES_PASSWORD` and `NEO4J_PASSWORD` set), then run:
```bash
docker compose up --build
```

Services exposed:
- **Frontend Dashboard**: `http://localhost:3000`
- **FastAPI Backend & API Docs**: `http://localhost:8000` (`http://localhost:8000/docs`)
- **PostgreSQL**: `localhost:5432`
- **Neo4j Browser / Bolt**: `http://localhost:7474` / `bolt://localhost:7687`

---

## Running Tests & Experiments

**Pytest Suite:**
```bash
pytest
```

**Standalone Backend Pipeline Verification:**
```bash
python backend/verify_backend.py
```

**Research Experiments (EXP 1–7):**
```bash
python experiments/run_all_experiments.py
```

### Frozen Benchmark Highlights (`research/CAIP_FINAL_RESULTS.md`)

| Experiment | Target Metric | Frozen Result |
| :--- | :--- | ---: |
| **EXP 1** | Alert Volume Reduction | **80.0%** (600 raw events → 120 campaigns) |
| **EXP 2** | Full Architecture F1 | **1.0000** |
| **EXP 3** | Multi-Signal Grouping F1 | **0.9421** |
| **EXP 4** | Known-Path Next-Stage Top-1 / Top-3 Accuracy | **90.37% / 99.82%** |
| **EXP 4-B** | Structurally Unseen-Path Top-1 / Top-3 Accuracy | **26.35% / 79.37%** |
| **EXP 5** | Digital Twin BLOCK F1 | **0.8163** |
| **EXP 6** | Cost-Aware Routing CPU Savings | **7.54%** |
| **EXP 7** | Archetype Holdout Top-1 Accuracy | **96.49%** |

> *Note: The evaluation demonstrates the feasibility of the proposed architecture under controlled benchmark conditions. Synthetic benchmark results and CICIDS2017-derived benchmark adapter evaluations should not be interpreted as real-world zero-day detection performance.*
