import pytest

from backend.models.evaluations import ZeroTrustEvaluation
from backend.models.events import NetworkEvent
from backend.services.deception import STRATEGY_SERVICE_MAP, deception_service


async def _make_evaluation(db_session, decision="DECEIVE"):
    event = NetworkEvent(
        source_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        source_port=1234,
        dest_port=80,
        protocol="TCP",
        packet_count=1,
        bytes_sent=10,
        bytes_received=10,
        connection_rate=1.0,
        failed_login_count=0,
        session_duration=1.0,
        dataset_source="test",
    )
    db_session.add(event)
    await db_session.flush()
    evaluation = ZeroTrustEvaluation(
        event_id=event.id,
        identity_score=0.9,
        device_score=0.9,
        behaviour_score=0.9,
        context_score=0.9,
        network_score=0.9,
        composite_risk_score=0.9,
        trust_decision=decision,
        evaluation_details={},
    )
    db_session.add(evaluation)
    await db_session.flush()
    return evaluation


@pytest.mark.asyncio
async def test_all_five_decoys_return_controlled_responses(db_session):
    decoy_strategies = [
        "FAKE_SSH",
        "FAKE_WEB",
        "FAKE_DB",
        "FAKE_CREDENTIALS",
        "DIGITAL_TWIN",
    ]
    for strategy in decoy_strategies:
        evaluation = await _make_evaluation(db_session)
        action = await deception_service.decide(db_session, evaluation, strategy)
        service_type = STRATEGY_SERVICE_MAP[strategy]
        result = await deception_service.record_interaction(
            db_session, action, "sess", service_type, "probe input"
        )
        assert result["is_sandboxed"] is True
        assert isinstance(result["response_text"], str) and result["response_text"]
        assert result["latency_ms"] >= 0.0
        assert action.interaction_log
        last = action.interaction_log[-1]
        assert last["input"] == "probe input"
        assert last["response_text"] == result["response_text"]
        assert "started_at" in last and "ended_at" in last
        assert "latency_ms" in last


@pytest.mark.asyncio
async def test_canary_is_test_signal_not_success(db_session):
    evaluation = await _make_evaluation(db_session)
    action = await deception_service.decide(db_session, evaluation, "FAKE_SSH")
    result = await deception_service.record_interaction(
        db_session, action, "sess", "ssh", "CANARY probe"
    )
    assert result["canary_triggered"] is True
    assert action.deception_success is False
