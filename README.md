# Adaptive AI-Based Cyber Deception Framework for Zero Trust Enterprise Networks

An academic research platform investigating the integration of AI-based behavioural threat detection, Zero Trust continuous risk evaluation, dynamic reinforcement-learning-guided cyber deception, LLM-assisted honeypot interaction, SHAP explainable AI, and federated learning.

**Base Paper Reference:**  
Anwar et al. (2022), *"Honeypot Allocation for Cyber Deception Under Uncertainty"*, IEEE Transactions on Network and Service Management.

---

## Architecture Overview

The runtime pipeline is:

```text
Event ingestion
	-> 14-feature engineering
	-> RF/XGBoost/PyTorch threat ensemble
	-> SHAP explanation
	-> Zero Trust risk score
	-> deception strategy selection
	-> honeypot response and interaction logging
	-> WebSocket event stream
	-> React SOC dashboard
```

The backend is a FastAPI application using async SQLAlchemy. SQLite is the local
default; PostgreSQL can be selected with `DATABASE_URL`.

Threat detection combines Random Forest, XGBoost, and a PyTorch MLP. The result
is stored with confidence, feature contributions, and a natural-language
explanation. The Zero Trust engine scores identity, device, behaviour, context,
and network risk, then returns `ALLOW`, `VERIFY`, `RESTRICT`, `DECEIVE`, or
`BLOCK`.

Deception supports Fake SSH, Fake Web, Fake DB, Fake Credentials, and Digital
Twin services. Local honeypot services are simulators. Docker Compose also
contains isolated internal honeypot containers for deployment testing.

The project includes both a native PyTorch DQN and a Gymnasium/
Stable-Baselines3 DQN. Flower `NumPyClient` and FedAvg adapters are available
for federated learning across HR, Finance, and Engineering data partitions.

---

## Quickstart

### Prerequisites
- Python 3.11+
- Python 3.11
- Node.js and npm for the dashboard
- Docker and Docker Compose for the containerized stack

### Installation
```bash
# Clone and enter directory
git clone <repo-url>
cd Final

# Create a virtual environment and install backend, ML, RL, Flower, and test dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Or use the repository's mise configuration
mise install
mise exec -- python -m pip install -e ".[dev]"
```

### Seeding Data & Generating Benchmark
```bash
# Generate 10,000 benchmark dataset records
python scripts/download_dataset.py

# Seed database with initial events
python scripts/seed_data.py
```

### Run the API

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The API is available at `http://127.0.0.1:8000`.

- OpenAPI docs: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/api/v1/system/health`
- WebSocket stream: `ws://127.0.0.1:8000/ws/events`

On startup, the application creates database tables and loads saved threat
detection models when they are available.

### Run the dashboard

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite dashboard is normally available at `http://localhost:5173`. Set
`VITE_API_URL` when the API is hosted elsewhere:

```bash
VITE_API_URL=http://127.0.0.1:8000 npm run dev
```

To create a production frontend bundle:

```bash
npm run build
```

### Run with Docker Compose

From the repository root:

```bash
docker compose up --build
```

This starts the API on port `8000`, the Nginx-served dashboard on port `3000`,
and five internal honeypot services on the `deception` network. The honeypot
containers are safe HTTP simulators for development, not production SSH,
database, or credential systems.

### Run tests

```bash
pytest -q
```

The integration tests use an in-memory SQLite database and cover event
generation, detection, Zero Trust evaluation, deception, and interaction.

## Workflows

### Generate and detect an event

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events/generate \
	-H 'Content-Type: application/json' \
	-d '{"scenario":"bruteforce","count":1}'

curl -X POST http://127.0.0.1:8000/api/v1/detection/detect \
	-H 'Content-Type: application/json' \
	-d '{"event_id":"EVENT_ID"}'
```

### Evaluate Zero Trust and select deception

```bash
curl -X POST http://127.0.0.1:8000/api/v1/zerotrust/evaluate \
	-H 'Content-Type: application/json' \
	-d '{"event_id":"EVENT_ID"}'

curl -X POST http://127.0.0.1:8000/api/v1/deception/decide \
	-H 'Content-Type: application/json' \
	-d '{"evaluation_id":"EVALUATION_ID"}'
```

The end-to-end API simulator runs this workflow automatically and records a
canary interaction:

```bash
python scripts/simulate_deception.py --base-url http://127.0.0.1:8000
```

### Train and inspect RL policies

Native PyTorch policy:

```bash
curl -X POST 'http://127.0.0.1:8000/api/v1/rl/train?episodes=100'
curl http://127.0.0.1:8000/api/v1/rl/policy
curl -X POST 'http://127.0.0.1:8000/api/v1/rl/evaluate?episodes=100'
```

Stable-Baselines3 DQN:

```bash
curl -X POST 'http://127.0.0.1:8000/api/v1/rl/train/stable-baselines?timesteps=1000'
```

After training, live deception decisions prefer the trained Stable-Baselines3
model, then fall back to the native PyTorch policy and finally the deterministic
rule-based selector.

### Run federated learning

```bash
curl -X POST 'http://127.0.0.1:8000/api/v1/federated/start?rounds=20&samples_per_client=20'
curl 'http://127.0.0.1:8000/api/v1/federated/rounds?limit=20'
```

The Flower adapter is available in `federated/flower_client.py`; the local
simulation uses weighted FedAvg and shares model parameters and metrics rather
than raw event records.

### Run research experiments

```bash
python experiments/run_experiments.py \
	--rounds 5 \
	--episodes 100 \
	--output data/experiments/results.json
```

This writes JSON results and PNG plots for RL baselines and federated
convergence.

### Generate data and train detection models
```bash
python scripts/download_dataset.py
python ml/train.py
python scripts/seed_data.py
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
├── data/               # Available benchmark data and generated datasets
├── ml/                 # Machine learning models, training, evaluatioOnly non-blocking warnings remain from SHAP deprecations and the Lucide/Vite bundler directive.n
├── rl/                 # Reinforcement learning Gymnasium environment & DQN agent
├── honeypots/          # Containerized development honeypot simulators
├── backend/services/   # Deception, honeypot, ingestion, risk, and detection services
├── federated/          # Flower federated learning coordinator & clients
├── frontend/           # React SOC Dashboard
├── experiments/        # Research evaluation scripts and data
├── scripts/            # Database seeding, benchmark generation
└── tests/              # Unit and integration test suites
```
