import pytest
import numpy as np
import pandas as pd
from backend.services.feature_engineering import feature_pipeline


def test_extract_features_from_dict_defaults():
    raw = {
        "dest_port": 80,
        "protocol": "TCP",
        "packet_count": 10,
        "bytes_sent": 1000,
        "bytes_received": 2000,
        "connection_rate": 2.5,
        "failed_login_count": 0,
        "session_duration": 4.0,
    }
    feat = feature_pipeline.extract_features_from_dict(raw)
    
    assert feat["dest_port"] == 80.0
    assert feat["protocol_num"] == 6.0  # TCP
    assert feat["packet_count"] == 10.0
    assert feat["bytes_sent"] == 1000.0
    assert feat["bytes_received"] == 2000.0
    assert feat["connection_rate"] == 2.5
    assert feat["failed_login_count"] == 0.0
    assert feat["session_duration"] == 4.0
    assert pytest.approx(feat["bytes_ratio"], 0.01) == 1000.0 / 2001.0
    assert feat["is_privileged_port"] == 1.0  # 80 < 1024
    assert pytest.approx(feat["packets_per_second"], 0.01) == 10.0 / 4.0


def test_privileged_port_flag():
    raw_high = {"dest_port": 8080}
    raw_low = {"dest_port": 443}
    
    feat_high = feature_pipeline.extract_features_from_dict(raw_high)
    feat_low = feature_pipeline.extract_features_from_dict(raw_low)
    
    assert feat_high["is_privileged_port"] == 0.0
    assert feat_low["is_privileged_port"] == 1.0


def test_to_feature_vector_shape_and_type():
    raw = {"dest_port": 22, "protocol": "SSH"}
    vec = feature_pipeline.to_feature_vector(raw)
    
    assert isinstance(vec, np.ndarray)
    assert vec.dtype == np.float32
    assert len(vec) == len(feature_pipeline.feature_names)


def test_transform_dataframe():
    data = [
        {"dest_port": 80, "protocol": "TCP", "packet_count": 5},
        {"dest_port": 443, "protocol": "TCP", "packet_count": 12},
        {"dest_port": 22, "protocol": "TCP", "packet_count": 30},
    ]
    df = pd.DataFrame(data)
    transformed = feature_pipeline.transform_dataframe(df)
    
    assert isinstance(transformed, pd.DataFrame)
    assert list(transformed.columns) == feature_pipeline.feature_names
    assert len(transformed) == 3
