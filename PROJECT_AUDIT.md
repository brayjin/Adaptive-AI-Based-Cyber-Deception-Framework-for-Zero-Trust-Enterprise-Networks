# Project Audit Report

## 1. Current Architecture

- **Entry point**: `backend/main.py` (FastAPI app, `backend.main:app`), confirmed by README, Dockerfile CMD, and uvicorn invocation.
- **Config**: `backend/config.py` (pydantic-settings), `.env` defaults to SQLite.
- **DB**: `backend/database.py` async SQLAlchemy engine/session; `Base.metadata.create_all` on startup.
- **Routing**: `backend/api/router.py` aggregates 8 routers under `/api/v1` plus `/ws/events` stream router.
- **Models (ORM)**: `backend/models/` — `NetworkEvent`, `ThreatPrediction`, `ZeroTrustEvaluation`, `DeceptionAction`, `ModelMetric`, `FederatedRound`, `SystemLog`.
- **Schemas**: `backend/schemas/` Pydantic request/response models.
- **Services**: `backend/services/` — data ingestion, feature engineering, synthetic data, threat detector, zero trust, risk scorer, deception, honeypots, LLM adapter, RL policy, federated simulation.
- **ML**: `ml/` — RF, XGBoost, PyTorch MLP, ensemble, SHAP explainer, training script.
- **RL**: `rl/` — Gymnasium env + SB3 DQN training.
- **Federated**: `federated/` — client, Flower adapter, FedAvg server.
- **Honeypots**: `honeypots/service.py` isolated container service.
- **Frontend**: React/Vite single-file dashboard (`frontend/src/main.jsx`).
- **Tests**: `tests/unit` (5 files) and `tests/integration` (4 files), pytest-asyncio auto mode.

## 2. Actual Implementation Status

Implemented and wired:
- Event ingestion/generation/query/count endpoints.
- 14-feature engineering pipeline.
- Synthetic data generator (6 scenarios).
- Threat detection ensemble + heuristic fallback + SHAP explainer.
- Zero Trust 5-factor risk scorer + policy get/update.
- Deception service + 5 honeypot simulators + interaction logging + canary detection.
- Native PyTorch DQN + SB3 DQN training endpoint.
- Federated learning simulation (FedAvg) + Flower adapter.
- WebSocket event snapshot stream.
- React SOC dashboard (read-only metrics).
- Experiments script and dataset seeding.

## 3. Critical Defects

1. **Docker image is incomplete**: `Dockerfile` copies only `backend`, `ml`, `scripts`, `data/benchmark`. It omits `rl/`, `federated/`, and `honeypots/`. Consequently `/rl/*` and `/federated/*` endpoints fail at import/runtime in the container, and the honeypot container relies on a separate build context. Also `pyproject.toml` setuptools `include` omits `rl*` and `honeypots*`.
2. **No pretrained models in container**: `ml/saved_models` is not copied, so the containerized API runs in heuristic fallback mode unless models are mounted/trained.
3. **Startup model loading mismatch**: README states models load on startup via lifespan, but `backend/main.py` lifespan only calls `init_db()`. Model loading actually occurs lazily at import time of `threat_detector_service` singleton (module-level `_initialize`), which runs during app import — before lifespan. This works but is implicit and not reported.
4. **Heavy synchronous calls inside async endpoints**: `adaptive_policy.train`, `adaptive_policy.evaluate_baselines`, `federated_simulation.run`, and SB3 `train_dqn` are synchronous and invoked directly in async route handlers, blocking the event loop.
5. **Type annotation inconsistency**: `DeceptionAction.rl_action` declared `Mapped[int]` but column is `String(20)`; harmless at runtime but misleading.
6. **Risk scorer context inputs**: `ZeroTrustEngine` builds `event_data` without `time_of_day`, so `calculate_context_score` always defaults to 0.5; context risk is effectively never time-aware through the API path.
7. **Ad-hoc detection path returns ORM object**: works via `from_attributes`, but `latency_ms`/top features not persisted; minor.
8. **Environment cannot run tests**: repository `.venv` is incomplete (only `include/`), and only Python 3.14 is available system-wide, while project requires Python 3.11 and pinned dependencies are not installed. Test execution could not be verified in this environment.

## 4. Missing Functionality

- No dashboard write actions (trigger training, evaluate, decide) — read-only SOC view.
- No authentication/authorization (Zero Trust is evaluated per-event, but API is open).
- No pagination/total counts for some endpoints (e.g., deception actions has limit/offset but no total).
- No real honeypot network integration; simulators only.
- No model retraining endpoint exposed via API (only scripts/RL train).
- `ModelMetric` table exists but no code populates it from training.
- Federated rounds endpoint returns raw dict rows; not typed schema.
- No Alembic migrations actually present (dependency declared but no `alembic/` dir).
- `honeypots/service.py` generates TLS material via `os.system` (shell) — security concern.

## 5. Existing Test Coverage

Unit tests:
- `test_feature_engineering.py` — feature extraction, vector, dataframe.
- `test_synthetic_data.py` — scenario generation.
- `test_threat_detector.py` — RF/XGB/MLP/ensemble fit/predict/save/load.
- `test_zero_trust.py` — risk scorer factors, composite decisions, normalization.
- `test_explainer.py` — heuristic + tree SHAP explainer.

Integration tests:
- `test_api_events.py` — health, root, generate, query, count, batch ingest.
- `test_api_detection.py` — inline/id detection, explain, query predictions, model metrics.
- `test_api_zerotrust.py` — evaluate inline/id, query/get, policy get/update.
- `test_end_to_end.py` — event → detection → ZT → deception → interact.

Not covered: deception service unit tests, RL modules, federated modules, honeypot registry, LLM adapter, WebSocket stream, frontend.

Test execution status: **UNVERIFIED** (no Python 3.11 runtime or installed dependencies in this environment). Reported pass counts in `docs/ROADMAP.md` could not be reproduced here.

## 6. Recommended Repair Order

1. Restore runnable environment (Python 3.11 + dependencies) and verify tests.
2. Fix Docker packaging (include `rl`, `federated`, `honeypots`, `ml/saved_models` or document volume mount).
3. Make model loading explicit in lifespan and log status.
4. Offload synchronous heavy operations (training, federated) to background tasks or threadpool.
5. Add missing test coverage for deception, RL, federated, honeypots, WebSocket.
6. Persist `ModelMetric` records from training; add typed schemas for federated rounds.
7. Add authentication/authorization if required by deployment.
8. Address `os.system` TLS generation in honeypot service.
