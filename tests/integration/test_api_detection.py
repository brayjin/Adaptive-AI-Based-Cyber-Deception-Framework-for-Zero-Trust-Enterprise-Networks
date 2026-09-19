import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_detect_with_inline_event_data(client: AsyncClient):
    payload = {
        "event_data": {
            "source_ip": "203.0.113.5",
            "dest_ip": "10.0.0.10",
            "source_port": 49152,
            "dest_port": 22,
            "protocol": "TCP",
            "packet_count": 50,
            "bytes_sent": 3000,
            "bytes_received": 1500,
            "connection_rate": 25.0,
            "failed_login_count": 12,
            "session_duration": 4.5,
        }
    }
    response = await client.post("/api/v1/detection/detect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] in ["BENIGN", "MALICIOUS"]
    assert 0.0 <= data["confidence"] <= 1.0
    assert "explanation" in data
    assert "feature_contributions" in data
    assert "event_id" in data


@pytest.mark.asyncio
async def test_detect_with_event_id(client: AsyncClient):
    # 1. Generate an event first
    gen_resp = await client.post("/api/v1/events/generate", json={"scenario": "portscan", "count": 1})
    assert gen_resp.status_code == 201
    event_id = gen_resp.json()["event_ids"][0]

    # 2. Run detection on that event ID
    detect_resp = await client.post("/api/v1/detection/detect", json={"event_id": event_id})
    assert detect_resp.status_code == 200
    data = detect_resp.json()
    assert data["event_id"] == event_id
    assert data["prediction"] in ["BENIGN", "MALICIOUS"]
    assert len(data["explanation"]) > 0


@pytest.mark.asyncio
async def test_explain_prediction_endpoint(client: AsyncClient):
    # Detect an event first
    detect_resp = await client.post(
        "/api/v1/detection/detect",
        json={
            "event_data": {
                "source_ip": "203.0.113.19",
                "dest_ip": "10.0.0.20",
                "dest_port": 80,
                "packet_count": 2000,
                "connection_rate": 150.0,
                "failed_login_count": 0,
            }
        }
    )
    pred_id = detect_resp.json()["id"]

    # Explain that prediction
    explain_resp = await client.get(f"/api/v1/detection/predictions/{pred_id}/explain")
    assert explain_resp.status_code == 200
    data = explain_resp.json()
    assert data["prediction_id"] == pred_id
    assert "top_features" in data
    assert len(data["top_features"]) > 0
    assert "explanation" in data


@pytest.mark.asyncio
async def test_query_predictions_endpoint(client: AsyncClient):
    # Query recent predictions
    response = await client.get("/api/v1/detection/predictions?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_models_metrics_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/detection/models/metrics")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
