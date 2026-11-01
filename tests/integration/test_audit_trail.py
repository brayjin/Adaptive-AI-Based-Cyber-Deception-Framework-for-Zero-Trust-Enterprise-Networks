import pytest

from backend.models.evaluations import ZeroTrustEvaluation
from backend.models.events import NetworkEvent
from backend.services.audit_trail import reconstruct_audit_chain
from backend.services.deception import deception_service


async def _setup_chain(db_session):
    event = NetworkEvent(
        source_ip="203.0.113.5",
        dest_ip="10.0.0.10",
        source_port=49152,
        dest_port=22,
        protocol="TCP",
        packet_count=50,
        bytes_sent=3000,
        bytes_received=1500,
        connection_rate=25.0,
        failed_login_count=12,
        session_duration=4.5,
        dataset_source="test",
    )
    db_session.add(event)
    await db_session.flush()

    prediction = None
    # Use threat detector to create prediction if available; otherwise create manually
    from backend.models.predictions import ThreatPrediction

    prediction = ThreatPrediction(
        event_id=event.id,
        prediction="MALICIOUS",
        confidence=0.9,
        model_version="ensemble_v1.0",
        feature_contributions={"failed_login_count": 0.4},
        explanation="test explanation",
    )
    db_session.add(prediction)
    await db_session.flush()

    evaluation = ZeroTrustEvaluation(
        event_id=event.id,
        prediction_id=prediction.id,
        identity_score=0.9,
        device_score=0.9,
        behaviour_score=0.9,
        context_score=0.9,
        network_score=0.9,
        composite_risk_score=0.9,
        trust_decision="DECEIVE",
        evaluation_details={"policy_weights": {"identity": 0.2}},
    )
    db_session.add(evaluation)
    await db_session.flush()

    action = await deception_service.decide(db_session, evaluation, "FAKE_SSH")
    await deception_service.record_interaction(
        db_session, action, "sess-1", "ssh", "CANARY whoami"
    )
    await db_session.flush()
    return event, prediction, evaluation, action


@pytest.mark.asyncio
async def test_audit_chain_reconstruction(db_session):
    event, prediction, evaluation, action = await _setup_chain(db_session)

    chain = await reconstruct_audit_chain(db_session, event.id)
    assert chain["event"].id == event.id
    assert len(chain["predictions"]) == 1
    assert chain["predictions"][0].id == prediction.id
    assert chain["predictions"][0].feature_contributions == {"failed_login_count": 0.4}

    assert len(chain["evaluations"]) == 1
    rec = chain["evaluations"][0]
    assert rec["evaluation"].id == evaluation.id
    assert rec["evaluation"].trust_decision == "DECEIVE"
    assert rec["evaluation"].composite_risk_score == 0.9
    assert rec["prediction"].id == prediction.id

    assert len(rec["deception_actions"]) == 1
    action_rec = rec["deception_actions"][0]
    assert action_rec["action"].id == action.id
    assert action_rec["action"].strategy_selected == "FAKE_SSH"
    assert action_rec["action"].strategy_reason  # preserved
    interactions = action_rec["interactions"]
    assert len(interactions) == 1
    entry = interactions[0]
    assert entry["input"] == "CANARY whoami"
    assert "response_text" in entry
    assert "started_at" in entry and "ended_at" in entry
    assert "latency_ms" in entry
