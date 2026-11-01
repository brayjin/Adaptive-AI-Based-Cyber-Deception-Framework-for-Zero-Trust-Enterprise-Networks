import numpy as np
import pytest

from backend.config import settings
from backend.services.feature_engineering import feature_pipeline


def test_all_fourteen_features_present():
    raw = {"dest_port": 22, "protocol": "SSH", "port_diversity": 7}
    vec = feature_pipeline.to_feature_vector(raw)
    assert isinstance(vec, np.ndarray)
    assert vec.dtype == np.float32
    assert len(vec) == 14
    assert len(settings.FEATURE_NAMES) == 14


def test_feature_ordering_consistent():
    raw = {"dest_port": 80, "protocol": "TCP", "packet_count": 5, "port_diversity": 3}
    feat = feature_pipeline.extract_features_from_dict(feature_pipeline.merge_computed_features(raw))
    assert list(feat.keys()) == settings.FEATURE_NAMES
    vec = feature_pipeline.to_feature_vector(raw)
    for i, name in enumerate(settings.FEATURE_NAMES):
        assert vec[i] == pytest.approx(feat[name], rel=1e-6)


def test_derived_features_survive_merge():
    original_pd = 42
    event_dict = {
        "dest_port": 80,
        "protocol": "TCP",
        "packet_count": 10,
        "bytes_sent": 100,
        "bytes_received": 200,
        "connection_rate": 2.0,
        "failed_login_count": 0,
        "session_duration": 4.0,
        "raw_features": {"computed_features": {"port_diversity": original_pd}},
    }
    merged = feature_pipeline.merge_computed_features(event_dict)
    assert merged["port_diversity"] == original_pd
    vec = feature_pipeline.to_feature_vector(event_dict)
    idx = settings.FEATURE_NAMES.index("port_diversity")
    assert vec[idx] == pytest.approx(original_pd, rel=1e-6)


def test_missing_values_handled():
    vec = feature_pipeline.to_feature_vector({})
    assert len(vec) == 14
    assert np.all(np.isfinite(vec))


def test_invalid_values_handled():
    raw = {
        "dest_port": "not-a-number",
        "packet_count": None,
        "session_duration": "abc",
        "port_diversity": "x",
    }
    with pytest.raises(ValueError):
        feature_pipeline.to_feature_vector(raw)
