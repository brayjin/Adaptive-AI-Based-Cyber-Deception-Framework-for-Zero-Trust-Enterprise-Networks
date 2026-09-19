import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_evaluate_inline_event_endpoint(client: AsyncClient):
    payload = {
        "event_data": {
            "source_ip": "203.0.113.101",
            "dest_ip": "10.0.0.10",
            "dest_port": 22,
            "protocol": "TCP",
            "packet_count": 35,
            "failed_login_count": 18,
            "connection_rate": 22.0,
            "session_duration": 1.5,
        }
    }
    response = await client.post("/api/v1/zerotrust/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "composite_risk_score" in data
    assert data["trust_decision"] in ["RESTRICT", "DECEIVE", "BLOCK"]
    assert data["identity_score"] > 0.5
    assert data["behaviour_score"] > 0.5
    assert "event_id" in data


@pytest.mark.asyncio
async def test_evaluate_with_event_id_and_prediction(client: AsyncClient):
    # 1. Generate an event
    gen_resp = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    event_id = gen_resp.json()["event_ids"][0]

    # 2. Run detection first
    detect_resp = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    pred_id = detect_resp.json()["id"]

    # 3. Evaluate Zero Trust passing both event_id and prediction_id
    eval_resp = await client.post(
        "/api/v1/zerotrust/evaluate",
        json={"event_id": event_id, "prediction_id": pred_id},
    )
    assert eval_resp.status_code == 200
    data = eval_resp.json()
    assert data["event_id"] == event_id
    assert data["prediction_id"] == pred_id
    assert data["trust_decision"] in ["RESTRICT", "DECEIVE", "BLOCK"]


@pytest.mark.asyncio
async def test_query_evaluations_and_get_by_id(client: AsyncClient):
    # Evaluate an event first
    eval_resp = await client.post(
        "/api/v1/zerotrust/evaluate",
        json={
            "event_data": {
                "source_ip": "10.0.1.55",
                "dest_ip": "10.0.0.20",
                "dest_port": 443,
                "packet_count": 15,
                "failed_login_count": 0,
            }
        },
    )
    eval_id = eval_resp.json()["id"]

    # Query list
    list_resp = await client.get("/api/v1/zerotrust/evaluations?limit=10")
    assert list_resp.status_code == 200
    evals = list_resp.json()
    assert len(evals) > 0

    # Get single evaluation
    single_resp = await client.get(f"/api/v1/zerotrust/evaluations/{eval_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["id"] == eval_id


@pytest.mark.asyncio
async def test_get_and_update_policy_endpoint(client: AsyncClient):
    # Get current policy
    get_resp = await client.get("/api/v1/zerotrust/policy")
    assert get_resp.status_code == 200
    initial_policy = get_resp.json()
    assert "weight_behaviour" in initial_policy

    # Update policy
    updated_payload = {
        "weight_identity": 0.25,
        "weight_device": 0.15,
        "weight_behaviour": 0.30,
        "weight_context": 0.15,
        "weight_network": 0.15,
        "threshold_allow": 0.15,
        "threshold_verify": 0.35,
        "threshold_restrict": 0.55,
        "threshold_deceive": 0.75,
    }
    put_resp = await client.put("/api/v1/zerotrust/policy", json=updated_payload)
    assert put_resp.status_code == 200
    res = put_resp.json()
    assert res["threshold_deceive"] == 0.75
    assert res["weight_identity"] == 0.25
