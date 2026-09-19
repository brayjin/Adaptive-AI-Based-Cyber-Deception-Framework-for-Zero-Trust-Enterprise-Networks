# Adaptive AI-Based Cyber Deception Framework for Zero Trust Enterprise Networks

An academic research platform investigating the integration of AI-based behavioural threat detection, Zero Trust continuous risk evaluation, dynamic reinforcement-learning-guided cyber deception, LLM-assisted honeypot interaction, SHAP explainable AI, and federated learning.

**Base Paper Reference:**  
Anwar et al. (2022), *"Honeypot Allocation for Cyber Deception Under Uncertainty"*, IEEE Transactions on Network and Service Management.

---

## 🏛️ Architecture Overview

The system operates according to an integrated security pipeline:
1. **Data Ingestion & Feature Engineering**: Extracts 14 derived and normalized features from raw telemetry.
2. **AI Threat Detection**: Multi-model ensemble (Random Forest, XGBoost, PyTorch MLP).
3. **Explainable AI**: SHAP feature importance and natural language rationale.
4. **Zero Trust Engine**: Multi-factor trust evaluation (Identity, Device, Behaviour, Context, Network) yielding decisions: `ALLOW`, `VERIFY`, `RESTRICT`, `DECEIVE`, `BLOCK`.
5. **Adaptive Cyber Deception**: Dynamic strategy selection (Fake SSH, Fake Web, Fake DB, Fake Credentials, Digital Twin redirect).
6. **Reinforcement Learning**: Deep Q-Network (DQN) optimizes deception engagement and intelligence gathering under uncertainty.
7. **LLM Sandbox**: Sandboxed local LLM generates realistic deceptive responses with strict security guardrails.
8. **Federated Learning**: Simulates privacy-preserving cross-domain threat learning via FedAvg.
9. **SOC Dashboard**: React web console for real-time threat monitoring and experimentation.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+
- Virtual environment (`venv`)

### Installation
```bash
# Clone and enter directory
git clone <repo-url>
cd Final

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Seeding Data & Generating Benchmark
```bash
# Generate 10,000 benchmark dataset records
python scripts/download_dataset.py

# Seed database with initial events
python scripts/seed_data.py
```

### Running the API Server
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Docs: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/api/v1/system/health`

### Running the Test Suite
```bash
pytest -v
```

---

## 📁 Repository Structure

```
├── backend/
│   ├── api/            # REST API routers (events, health, etc.)
│   ├── config.py       # Pydantic Settings & environment config
│   ├── database.py     # SQLAlchemy 2.0 async engine & session management
│   ├── models/         # ORM models (events, predictions, evaluations, deception, metrics, federated)
│   ├── schemas/        # Pydantic validation schemas
│   ├── services/       # Core business logic (feature engineering, ingestion, synthetic generator)
│   └── utils/          # Structured logging & helpers
├── data/               # Datasets (benchmark, CICIDS2017, UNSW-NB15)
├── ml/                 # Machine learning models, training, evaluation
├── rl/                 # Reinforcement learning Gymnasium environment & DQN agent
├── deception/          # Digital Twin honeypot services
├── federated/          # Flower federated learning coordinator & clients
├── frontend/           # React SOC Dashboard
├── experiments/        # Research evaluation scripts and data
├── scripts/            # Database seeding, benchmark generation
└── tests/              # Unit and integration test suites
```
