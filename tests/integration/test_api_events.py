import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/system/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["ONLINE", "DEGRADED"]
    assert "active_components" in data
    assert data["database"] == "HEALTHY"


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert "api_v1" in data


@pytest.mark.asyncio
async def test_generate_synthetic_events_endpoint(client: AsyncClient):
    payload = {"scenario": "mixed", "count": 25}
    response = await client.post("/api/v1/events/generate", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["ingested_count"] == 25
    assert len(data["event_ids"]) == 25


@pytest.mark.asyncio
async def test_query_events_endpoint(client: AsyncClient):
    # First generate events
    await client.post("/api/v1/events/generate", json={"scenario": "bruteforce", "count": 10})
    
    # Query events
    response = await client.get("/api/v1/events?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 10
    assert "source_ip" in data[0]
    assert "dest_port" in data[0]


@pytest.mark.asyncio
async def test_event_count_endpoint(client: AsyncClient):
    # Generate 15 events
    await client.post("/api/v1/events/generate", json={"scenario": "ddos", "count": 15})
    
    response = await client.get("/api/v1/events/count")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] >= 15


@pytest.mark.asyncio
async def test_batch_ingest_endpoint(client: AsyncClient):
    batch = {
        "dataset_source": "test_batch",
        "events": [
            {
                "source_ip": "10.0.1.50",
                "dest_ip": "10.0.0.10",
                "source_port": 50123,
                "dest_port": 443,
                "protocol": "TCP",
                "packet_count": 12,
                "bytes_sent": 1200,
                "bytes_received": 3400,
                "connection_rate": 1.2,
                "failed_login_count": 0,
                "session_duration": 5.4,
                "raw_features": {"tag": "manual_test"},
                "dataset_source": "test_batch",
            }
        ]
    }
    response = await client.post("/api/v1/events/ingest", json=batch)
    assert response.status_code == 201
    data = response.json()
    assert data["ingested_count"] == 1
    assert len(data["event_ids"]) == 1
