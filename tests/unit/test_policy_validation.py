import math

import pytest
from pydantic import ValidationError

from backend.services.risk_scorer import ZeroTrustPolicy


def test_default_weights_and_thresholds():
    p = ZeroTrustPolicy()
    assert p.weight_identity == 0.20
    assert p.weight_device == 0.15
    assert p.weight_behaviour == 0.35
    assert p.weight_context == 0.15
    assert p.weight_network == 0.15
    assert p.threshold_allow == 0.20
    assert p.threshold_verify == 0.40
    assert p.threshold_restrict == 0.60
    assert p.threshold_deceive == 0.80


def test_valid_custom_weights_normalize():
    p = ZeroTrustPolicy(
        weight_identity=0.10,
        weight_device=0.10,
        weight_behaviour=0.10,
        weight_context=0.10,
        weight_network=0.10,
    )
    total = (
        p.weight_identity
        + p.weight_device
        + p.weight_behaviour
        + p.weight_context
        + p.weight_network
    )
    assert abs(total - 1.0) < 1e-9


def test_all_zero_weights_rejected():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(
            weight_identity=0,
            weight_device=0,
            weight_behaviour=0,
            weight_context=0,
            weight_network=0,
        )


def test_negative_weight_rejected():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(
            weight_identity=-0.2,
            weight_device=0.3,
            weight_behaviour=0.4,
            weight_context=0.2,
            weight_network=0.3,
        )


def test_nan_and_inf_rejected():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(
            weight_identity=float("nan"),
            weight_device=0.15,
            weight_behaviour=0.35,
            weight_context=0.15,
            weight_network=0.15,
        )
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(
            weight_identity=float("inf"),
            weight_device=0.15,
            weight_behaviour=0.35,
            weight_context=0.15,
            weight_network=0.15,
        )


def test_invalid_type_rejected():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(
            weight_identity="0.2",
            weight_device=0.15,
            weight_behaviour=0.35,
            weight_context=0.15,
            weight_network=0.15,
        )


def test_thresholds_must_increase():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(threshold_allow=0.5, threshold_verify=0.4, threshold_restrict=0.6, threshold_deceive=0.8)
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(threshold_allow=0.2, threshold_verify=0.2, threshold_restrict=0.6, threshold_deceive=0.8)


def test_threshold_out_of_range_rejected():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(threshold_allow=-0.1, threshold_verify=0.4, threshold_restrict=0.6, threshold_deceive=0.8)
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(threshold_allow=0.2, threshold_verify=0.4, threshold_restrict=0.6, threshold_deceive=1.1)


def test_threshold_nan_inf_rejected():
    with pytest.raises(ValidationError):
        ZeroTrustPolicy(threshold_allow=float("nan"), threshold_verify=0.4, threshold_restrict=0.6, threshold_deceive=0.8)


def test_boundary_decisions():
    from backend.services.risk_scorer import RiskScorer

    scorer = RiskScorer()
    policy = ZeroTrustPolicy()
    event = {
        "dest_port": 443,
        "failed_login_count": 0,
        "time_of_day": 0.5,
        "session_duration": 15.0,
        "connection_rate": 1.0,
        "port_diversity": 1,
    }
    # Force composite near boundaries by using behaviour score? Use direct evaluate with prediction confidence adjustments is hard.
    # Instead test threshold constants and decision mapping via composite risk values indirectly through evaluate_composite_risk with extreme inputs.
    low = {"dest_port": 443, "failed_login_count": 0, "time_of_day": 0.5, "session_duration": 15.0, "connection_rate": 1.0, "port_diversity": 1}
    pred = {"prediction": "BENIGN", "confidence": 0.96}
    risk, scores, decision = scorer.evaluate_composite_risk(low, pred, policy)
    assert decision == "ALLOW"
    assert risk < 0.20
