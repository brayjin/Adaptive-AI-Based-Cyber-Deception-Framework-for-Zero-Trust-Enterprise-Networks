import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_audit_api_unknown_event_returns_404(client: AsyncClient):
    resp = await client.get("/api/v1/audit/events/does-not-exist")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_audit_api_reconstructs_chain(client: AsyncClient):
    generated = await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 1})
    assert generated.status_code == 201
    event_id = generated.json()["event_ids"][0]

    detection = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    assert detection.status_code == 200

    evaluation = await client.post(
        "/api/v1/zerotrust/evaluate",
        json={"event_id": event_id, "prediction_id": detection.json()["id"]},
    )
    assert evaluation.status_code == 200

    action = await client.post(
        "/api/v1/deception/decide", json={"evaluation_id": evaluation.json()["id"]}
    )
    assert action.status_code in (200, 201)

    strategy = action.json()["strategy_selected"]
    mapping = {
        "FAKE_SSH": "ssh",
        "FAKE_WEB": "web",
        "FAKE_DB": "db",
        "FAKE_CREDENTIALS": "credentials",
        "DIGITAL_TWIN": "digital_twin",
    }
    service_type = mapping.get(strategy)
    if service_type is not None:
        interaction = await client.post(
            "/api/v1/deception/interact",
            json={
                "action_id": action.json()["id"],
                "session_id": "audit-test",
                "service_type": service_type,
                "input_text": "probe",
            },
        )
        assert interaction.status_code == 200

    resp = await client.get(f"/api/v1/audit/events/{event_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_id"] == event_id
    assert data["status"] in ("complete", "incomplete")
    assert len(data["predictions"]) >= 1
    assert len(data["evaluations"]) >= 1
    ev = data["evaluations"][0]
    assert "identity_score" in ev
    assert ev["trust_decision"] is not None