import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_event_to_deception_pipeline(client: AsyncClient):
    generated = await client.post(
        "/api/v1/events/generate",
        json={"scenario": "bruteforce", "count": 1},
    )
    assert generated.status_code == 201
    event_id = generated.json()["event_ids"][0]

    detection = await client.post(
        "/api/v1/detection/detect",
        json={"event_id": event_id},
    )
    assert detection.status_code == 200

    evaluation = await client.post(
        "/api/v1/zerotrust/evaluate",
        json={"event_id": event_id, "prediction_id": detection.json()["id"]},
    )
    assert evaluation.status_code == 200

    action = await client.post(
        "/api/v1/deception/decide",
        json={"evaluation_id": evaluation.json()["id"]},
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
                "session_id": "integration-test",
                "service_type": service_type,
                "input_text": "CANARY whoami",
            },
        )
        assert interaction.status_code == 200
        assert interaction.json()["is_sandboxed"] is True
