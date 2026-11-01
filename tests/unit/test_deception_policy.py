import pytest

from backend.models.evaluations import ZeroTrustEvaluation
from backend.models.events import NetworkEvent
from backend.services.deception import STRATEGIES, deception_service


async def _make_evaluation(db_session, decision: str) -> ZeroTrustEvaluation:
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
        identity_score=0.1,
        device_score=0.1,
        behaviour_score=0.1,
        context_score=0.1,
        network_score=0.1,
        composite_risk_score=0.1 if decision == "ALLOW" else 0.9,
        trust_decision=decision,
        evaluation_details={},
    )
    db_session.add(evaluation)
    await db_session.flush()
    return evaluation


@pytest.mark.asyncio
async def test_all_six_strategies_selectable_for_deceive(db_session):
    decoys = [
        "FAKE_SSH",
        "FAKE_WEB",
        "FAKE_DB",
        "FAKE_CREDENTIALS",
        "DIGITAL_TWIN",
    ]
    for strategy in decoys:
        evaluation = await _make_evaluation(db_session, "DECEIVE")
        action = await deception_service.decide(db_session, evaluation, strategy)
        assert action.strategy_selected == strategy


@pytest.mark.asyncio
async def test_unauthorized_override_rejected_for_allow(db_session):
    evaluation = await _make_evaluation(db_session, "ALLOW")
    with pytest.raises(ValueError):
        await deception_service.decide(db_session, evaluation, "FAKE_SSH")


@pytest.mark.asyncio
async def test_benign_allow_defaults_to_normal_response(db_session):
    evaluation = await _make_evaluation(db_session, "ALLOW")
    action = await deception_service.decide(db_session, evaluation)
    assert action.strategy_selected == "NORMAL_RESPONSE"


@pytest.mark.asyncio
async def test_high_risk_not_normal_response(db_session):
    evaluation = await _make_evaluation(db_session, "DECEIVE")
    action = await deception_service.decide(db_session, evaluation)
    assert action.strategy_selected != "NORMAL_RESPONSE"


@pytest.mark.asyncio
async def test_invalid_strategy_rejected(db_session):
    evaluation = await _make_evaluation(db_session, "DECEIVE")
    with pytest.raises(ValueError):
        await deception_service.decide(db_session, evaluation, "NOT_A_STRATEGY")


@pytest.mark.asyncio
async def test_normal_response_no_decoy_interaction(db_session):
    evaluation = await _make_evaluation(db_session, "ALLOW")
    action = await deception_service.decide(db_session, evaluation, "NORMAL_RESPONSE")
    with pytest.raises(ValueError):
        await deception_service.record_interaction(
            db_session, action, "sess", "ssh", "hello"
        )


@pytest.mark.asyncio
async def test_service_type_mismatch_rejected(db_session):
    evaluation = await _make_evaluation(db_session, "DECEIVE")
    action = await deception_service.decide(db_session, evaluation, "FAKE_SSH")
    with pytest.raises(ValueError):
        await deception_service.record_interaction(
            db_session, action, "sess", "web", "hello"
        )


@pytest.mark.asyncio
async def test_verify_cannot_invoke_decoy(db_session):
    evaluation = await _make_evaluation(db_session, "VERIFY")
    with pytest.raises(ValueError):
        await deception_service.decide(db_session, evaluation, "FAKE_DB")


@pytest.mark.asyncio
async def test_restrict_cannot_invoke_decoy(db_session):
    evaluation = await _make_evaluation(db_session, "RESTRICT")
    with pytest.raises(ValueError):
        await deception_service.decide(db_session, evaluation, "FAKE_WEB")


@pytest.mark.asyncio
async def test_block_can_select_decoy(db_session):
    evaluation = await _make_evaluation(db_session, "BLOCK")
    action = await deception_service.decide(db_session, evaluation, "FAKE_SSH")
    assert action.strategy_selected == "FAKE_SSH"


@pytest.mark.asyncio
async def test_deceive_cannot_downgrade_to_normal(db_session):
    evaluation = await _make_evaluation(db_session, "DECEIVE")
    with pytest.raises(ValueError):
        await deception_service.decide(db_session, evaluation, "NORMAL_RESPONSE")


@pytest.mark.asyncio
async def test_block_cannot_downgrade_to_normal(db_session):
    evaluation = await _make_evaluation(db_session, "BLOCK")
    with pytest.raises(ValueError):
        await deception_service.decide(db_session, evaluation, "NORMAL_RESPONSE")


@pytest.mark.asyncio
async def test_rl_normal_response_cannot_bypass_policy(db_session, monkeypatch):
    from backend.services import rl_deception

    evaluation = await _make_evaluation(db_session, "DECEIVE")
    monkeypatch.setattr(rl_deception.adaptive_policy, "trained_episodes", 1)
    monkeypatch.setattr(rl_deception.adaptive_policy, "select_action", lambda state, explore=False: 5)
    action = await deception_service.decide(db_session, evaluation)
    assert action.strategy_selected != "NORMAL_RESPONSE"
    assert action.strategy_selected in {
        "FAKE_SSH",
        "FAKE_WEB",
        "FAKE_DB",
        "FAKE_CREDENTIALS",
        "DIGITAL_TWIN",
    }
