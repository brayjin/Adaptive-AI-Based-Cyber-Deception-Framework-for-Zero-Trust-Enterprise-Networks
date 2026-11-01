import pytest
from sqlalchemy import select

from backend.models.events import NetworkEvent
from backend.services.data_ingestion import data_ingestion_service
from backend.services.threat_detector import threat_detector_service


@pytest.mark.asyncio
async def test_computed_features_survive_persistence(db_session):
    events = [
        {
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
            "port_diversity": 37,
            "raw_features": {"tag": "test"},
        }
    ]
    ids = await data_ingestion_service.ingest_event_dict_batch(
        db=db_session, events_data=events, dataset_source="test"
    )
    assert len(ids) == 1

    result = await db_session.execute(
        select(NetworkEvent).where(NetworkEvent.id == ids[0])
    )
    event = result.scalar_one()
    computed = (event.raw_features or {}).get("computed_features", {})
    assert computed.get("port_diversity") == 37

    # Live inference should receive the original computed value
    prediction = await threat_detector_service.detect_and_record(db_session, event)
    assert prediction is not None
    assert prediction.event_id == event.id
