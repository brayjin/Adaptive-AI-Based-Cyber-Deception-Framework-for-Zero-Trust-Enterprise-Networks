import pytest
from httpx import AsyncClient

from backend.models.predictions import ThreatPrediction
from backend.models.events import NetworkEvent


@pytest.mark.asyncio
async def test_valid_event_and_own_prediction(client: AsyncClient):
    g = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    event_id = g.json()["event_ids"][0]
    d = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    pred_id = d.json()["id"]
    ev = await client.post("/api/v1/zerotrust/evaluate", json={"event_id": event_id, "prediction_id": pred_id})
    assert ev.status_code == 200
    assert ev.json()["prediction_id"] == pred_id
    assert ev.json()["event_id"] == event_id


@pytest.mark.asyncio
async def test_unknown_event_rejected(client: AsyncClient):
    resp = await client.post("/api/v1/zerotrust/evaluate", json={"event_id": "missing", "prediction_id": None})
    # event_id missing -> 404 (prediction_id None path still checks event existence)
    # Actually service needs event; API checks event existence for event_id
    assert resp.status_code in (400, 404)


@pytest.mark.asyncio
async def test_unknown_prediction_rejected(client: AsyncClient):
    g = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    event_id = g.json()["event_ids"][0]
    resp = await client.post("/api/v1/zerotrust/evaluate", json={"event_id": event_id, "prediction_id": "missing"})
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_mismatched_prediction_rejected(client: AsyncClient):
    g1 = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    g2 = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    e1 = g1.json()["event_ids"][0]
    e2 = g2.json()["event_ids"][0]
    d2 = await client.post("/api/v1/detection/detect", json={"event_id": e2})
    pred2 = d2.json()["id"]
    resp = await client.post("/api/v1/zerotrust/evaluate", json={"event_id": e1, "prediction_id": pred2})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_mismatched_does_not_create_evaluation(client: AsyncClient):
    g1 = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    g2 = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    e1 = g1.json()["event_ids"][0]
    e2 = g2.json()["event_ids"][0]
    d2 = await client.post("/api/v1/detection/detect", json={"event_id": e2})
    pred2 = d2.json()["id"]
    before = await client.get("/api/v1/zerotrust/evaluations?limit=100")
    before_count = len(before.json())
    await client.post("/api/v1/zerotrust/evaluate", json={"event_id": e1, "prediction_id": pred2})
    after = await client.get("/api/v1/zerotrust/evaluations?limit=100")
    assert len(after.json()) == before_count


@pytest.mark.asyncio
async def test_event_with_multiple_predictions(client: AsyncClient):
    g = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    event_id = g.json()["event_ids"][0]
    d1 = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    # detect again returns same prediction (duplicate prevention)
    d2 = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    assert d1.json()["id"] == d2.json()["id"]
    ev = await client.post("/api/v1/zerotrust/evaluate", json={"event_id": event_id, "prediction_id": d1.json()["id"]})
    assert ev.status_code == 200
    assert ev.json()["prediction_id"] == d1.json()["id"]