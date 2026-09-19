import pytest
from backend.services.risk_scorer import RiskScorer, ZeroTrustPolicy


@pytest.fixture
def policy():
    return ZeroTrustPolicy(
        weight_identity=0.20,
        weight_device=0.15,
        weight_behaviour=0.35,
        weight_context=0.15,
        weight_network=0.15,
        threshold_allow=0.20,
        threshold_verify=0.40,
        threshold_restrict=0.60,
        threshold_deceive=0.80,
    )


def test_identity_score_scaling():
    # 0 failed logins -> minimal risk
    s0 = RiskScorer.calculate_identity_score({"failed_login_count": 0})
    assert s0 <= 0.10

    # 5 failed logins -> medium risk
    s5 = RiskScorer.calculate_identity_score({"failed_login_count": 5})
    assert 0.40 < s5 < 0.70

    # 20 failed logins -> high risk approaching 1.0
    s20 = RiskScorer.calculate_identity_score({"failed_login_count": 20})
    assert s20 > 0.90


def test_device_score_privileged_ports():
    s_web = RiskScorer.calculate_device_score({"dest_port": 8080})
    s_ssh = RiskScorer.calculate_device_score({"dest_port": 22})
    s_rdp = RiskScorer.calculate_device_score({"dest_port": 3389})

    assert s_ssh > s_web
    assert s_rdp > s_web


def test_behaviour_score_driven_by_ai():
    # AI predicts MALICIOUS with 0.95 confidence
    s_mal = RiskScorer.calculate_behaviour_score({"prediction": "MALICIOUS", "confidence": 0.95})
    assert s_mal >= 0.90

    # AI predicts BENIGN with 0.95 confidence
    s_ben = RiskScorer.calculate_behaviour_score({"prediction": "BENIGN", "confidence": 0.95})
    assert s_ben <= 0.10


def test_composite_risk_evaluation_decisions(policy):
    scorer = RiskScorer()

    # Low risk benign scenario -> ALLOW
    benign_event = {
        "dest_port": 443,
        "failed_login_count": 0,
        "time_of_day": 0.5,
        "session_duration": 15.0,
        "connection_rate": 1.0,
        "port_diversity": 1,
    }
    benign_pred = {"prediction": "BENIGN", "confidence": 0.96}
    risk, scores, decision = scorer.evaluate_composite_risk(benign_event, benign_pred, policy)
    assert risk < policy.threshold_allow
    assert decision == "ALLOW"

    # Aggressive attack scenario -> DECEIVE or BLOCK
    attack_event = {
        "dest_port": 22,
        "failed_login_count": 15,
        "time_of_day": 0.1,  # 2 AM
        "session_duration": 0.05,
        "connection_rate": 50.0,
        "port_diversity": 35,
    }
    attack_pred = {"prediction": "MALICIOUS", "confidence": 0.98}
    risk_atk, scores_atk, decision_atk = scorer.evaluate_composite_risk(attack_event, attack_pred, policy)
    assert risk_atk >= policy.threshold_restrict
    assert decision_atk in ["DECEIVE", "BLOCK"]


def test_weight_normalization():
    p = ZeroTrustPolicy(
        weight_identity=0.10,
        weight_device=0.10,
        weight_behaviour=0.10,
        weight_context=0.10,
        weight_network=0.10,
    )
    p.normalize_weights()
    total = p.weight_identity + p.weight_device + p.weight_behaviour + p.weight_context + p.weight_network
    assert pytest.approx(total, 0.001) == 1.0
    assert pytest.approx(p.weight_identity, 0.001) == 0.20
