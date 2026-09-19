# Adaptive AI-Based Cyber Deception Framework for Zero Trust Enterprise Networks

## Complete Milestone Roadmap & Architecture Design

---

## A. Base Paper & Proposed Extensions

**Base Paper:** Anwar et al. (2022) — *Honeypot Allocation for Cyber Deception Under Uncertainty*, IEEE Transactions on Network and Service Management.

| Base Paper | Proposed Extensions |
|---|---|
| Honeypot allocation | Dynamic multi-strategy deception |
| Game-theoretic MCTS | Reinforcement Learning (DQN) |
| Static defender strategy | Adaptive policy learning |
| No detection layer | AI behavioural threat detection |
| No trust model | Zero Trust continuous evaluation |
| No attacker interaction | LLM-assisted deceptive interaction |
| No explainability | SHAP-based XAI |
| Single domain | Federated multi-domain learning |
| Theoretical model | Full-stack research prototype with SOC dashboard |

---

## B. Milestone Roadmap Overview

| # | Milestone | Core Deliverable | Complexity | Status |
|---|---|---|---|---|
| **M1** | Project Foundation & Data Pipeline | Working API server, database, data ingestion, feature engineering | Medium | ✅ Completed |
| **M2** | AI Threat Detection & Explainability | Trained ML models, SHAP explanations, evaluation metrics | High | ✅ Completed |
| **M3** | Zero Trust Engine & Risk Scoring | Continuous trust evaluation, risk scoring, policy decisions | Medium | ✅ Completed |
| **M4** | Cyber Deception & Digital Twin | Simulator honeypots, deception controller, Digital Twin | High | ✅ Completed |
| **M5** | RL Adaptive Deception & LLM Integration | PyTorch DQN agent, Ollama adapter, adaptive policy | High | ✅ Completed |
| **M6** | Federated Learning | Multi-domain simulation, client/server contracts, FedAvg | Medium | ✅ Completed |
| **M7** | SOC Dashboard, Integration & Evaluation | React dashboard, WebSocket stream, integration, experiments | High | ✅ Completed |

---

## C. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| **Language** | Python 3.11+ | Ecosystem maturity for ML/AI/security |
| **Backend API** | FastAPI | Async support, auto-generated OpenAPI docs, Pydantic validation |
| **Database** | PostgreSQL / SQLite (aiosqlite) | Async ORM, flexible JSON fields, zero-friction local execution |
| **ORM** | SQLAlchemy 2.0 | Async ORM, declarative models |
| **ML/DL** | scikit-learn, XGBoost, PyTorch | Random Forest, XGBoost, PyTorch MLP ensemble |
| **Reinforcement Learning** | Stable-Baselines3 + Gymnasium | Deep Q-Network (DQN) for adaptive deception selection |
| **LLM** | Ollama (Mistral 7B / Llama 3.2 3B) | Sandboxed local LLM for realistic deceptive interaction |
| **Explainability** | SHAP | TreeExplainer for feature importance & natural-language explanations |
| **Federated Learning** | Flower (flwr) | Multi-domain simulation engine with FedAvg |
| **Frontend** | React 18 + Vite + Recharts | Real-time SOC dashboard console |
| **Testing** | pytest, pytest-asyncio, httpx | 40+ unit and integration tests |

---

## D. Component Priority Classification

### Tier 1 — Essential (Core System)
- Data pipeline & 14-feature engineering
- AI threat detection ensemble (RF + XGBoost + PyTorch MLP)
- SHAP explainability
- Zero Trust multi-factor evaluation engine
- Controlled deception honeypots & Digital Twin
- RL adaptive deception policy
- SOC dashboard
- Experimental evaluation suite

### Tier 2 — Advanced (Research Extensions)
- LLM-assisted deceptive interaction sandbox
- Federated Learning simulation (Flower flwr)
- Dynamic policy adjustment via REST API
