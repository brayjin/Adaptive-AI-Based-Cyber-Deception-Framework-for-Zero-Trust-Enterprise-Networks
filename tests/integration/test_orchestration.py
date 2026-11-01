import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_complete_pipeline_high_risk(client: AsyncClient):
    generated = await client.post(
        "/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1}
    )
    assert generated.status_code == 201
    event_id = generated.json()["event_ids"][0]

    detection = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    assert detection.status_code == 200
    pred_id = detection.json()["id"]

    evaluation = await client.post(
        "/api/v1/zerotrust/evaluate",
        json={"event_id": event_id, "prediction_id": pred_id},
    )
    assert evaluation.status_code == 200
    eval_id = evaluation.json()["id"]

    action = await client.post(
        "/api/v1/deception/decide", json={"evaluation_id": eval_id}
    )
    assert action.status_code in (200, 201)
    strategy = action.json()["strategy_selected"]
    assert strategy != "NORMAL_RESPONSE"

    service_type = strategy.lower().replace("fake_", "").replace("digital_twin", "digital_twin")
    # map strategy to service type
    mapping = {
        "FAKE_SSH": "ssh",
        "FAKE_WEB": "web",
        "FAKE_DB": "db",
        "FAKE_CREDENTIALS": "credentials",
        "DIGITAL_TWIN": "digital_twin",
    }
    svc = mapping[strategy]
    interaction = await client.post(
        "/api/v1/deception/interact",
        json={
            "action_id": action.json()["id"],
            "session_id": "orch-test",
            "service_type": svc,
            "input_text": "probe",
        },
    )
    assert interaction.status_code == 200
    assert interaction.json()["is_sandboxed"] is True


@pytest.mark.asyncio
async def test_benign_event_cannot_reach_unauthorized_deception(client: AsyncClient):
    generated = await client.post(
        "/api/v1/events/generate", json={"scenario": "benign", "count": 1}
    )
    assert generated.status_code == 201
    event_id = generated.json()["event_ids"][0]

    detection = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    assert detection.status_code == 200
    pred_id = detection.json()["id"]

    evaluation = await client.post(
        "/api/v1/zerotrust/evaluate",
        json={"event_id": event_id, "prediction_id": pred_id},
    )
    assert evaluation.status_code == 200
    eval_id = evaluation.json()["id"]

    action = await client.post(
        "/api/v1/deception/decide", json={"evaluation_id": eval_id}
    )
    assert action.status_code in (200, 201)
    assert action.json()["strategy_selected"] == "NORMAL_RESPONSE"

    # Attempting to interact with a decoy must be rejected
    interaction = await client.post(
        "/api/v1/deception/interact",
        json={
            "action_id": action.json()["id"],
            "session_id": "orch-test",
            "service_type": "ssh",
            "input_text": "probe",
        },
    )
    assert interaction.status_code == 400


@pytest.mark.asyncio
async def test_duplicate_prediction_not_created(client: AsyncClient):
    generated = await client.post(
        "/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1}
    )
    event_id = generated.json()["event_ids"][0]
    first = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    second = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
