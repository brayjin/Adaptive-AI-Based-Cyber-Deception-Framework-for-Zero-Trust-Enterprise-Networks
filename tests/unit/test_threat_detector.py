import tempfile
from pathlib import Path
import numpy as np
import pytest
from ml.models.random_forest import RandomForestThreatModel
from ml.models.xgboost_model import XGBoostThreatModel
from ml.models.mlp import PyTorchMLPThreatModel
from ml.models.ensemble import EnsembleThreatDetector


@pytest.fixture
def synthetic_training_data():
    np.random.seed(42)
    # 200 samples, 14 features
    X = np.random.randn(200, 14).astype(np.float32)
    # Simple linearly separable target based on feature 0 and 6
    y = ((X[:, 0] + X[:, 6]) > 0).astype(np.int64)
    return X, y


def test_random_forest_fit_predict_save_load(synthetic_training_data):
    X, y = synthetic_training_data
    rf = RandomForestThreatModel(n_estimators=10, max_depth=5)
    rf.fit(X, y)
    
    assert rf.is_fitted
    preds = rf.predict(X[:10])
    probs = rf.predict_proba(X[:10])
    assert len(preds) == 10
    assert probs.shape == (10, 2)

    with tempfile.TemporaryDirectory() as tmpdir:
        save_path = Path(tmpdir) / "rf.joblib"
        rf.save(save_path)
        assert save_path.exists()
        
        rf2 = RandomForestThreatModel()
        rf2.load(save_path)
        assert rf2.is_fitted
        np.testing.assert_array_equal(rf.predict(X[:5]), rf2.predict(X[:5]))


def test_xgboost_fit_predict_save_load(synthetic_training_data):
    X, y = synthetic_training_data
    xgb_model = XGBoostThreatModel(n_estimators=10, max_depth=3)
    xgb_model.fit(X, y)

    assert xgb_model.is_fitted
    preds = xgb_model.predict(X[:10])
    probs = xgb_model.predict_proba(X[:10])
    assert len(preds) == 10
    assert probs.shape == (10, 2)

    with tempfile.TemporaryDirectory() as tmpdir:
        save_path = Path(tmpdir) / "xgb.joblib"
        xgb_model.save(save_path)
        assert save_path.exists()

        xgb2 = XGBoostThreatModel()
        xgb2.load(save_path)
        assert xgb2.is_fitted
        np.testing.assert_array_equal(xgb_model.predict(X[:5]), xgb2.predict(X[:5]))


def test_pytorch_mlp_fit_predict_and_fl_helpers(synthetic_training_data):
    X, y = synthetic_training_data
    mlp = PyTorchMLPThreatModel(input_dim=14, num_classes=2, lr=0.01)
    mlp.fit(X, y, epochs=5, batch_size=32)

    assert mlp.is_fitted
    preds = mlp.predict(X[:10])
    probs = mlp.predict_proba(X[:10])
    assert len(preds) == 10
    assert probs.shape == (10, 2)

    # Test Federated Learning parameter extraction and insertion
    params = mlp.get_parameters()
    assert len(params) > 0
    assert isinstance(params[0], np.ndarray)

    mlp.set_parameters(params)
    preds_after = mlp.predict(X[:10])
    np.testing.assert_array_equal(preds, preds_after)

    with tempfile.TemporaryDirectory() as tmpdir:
        save_path = Path(tmpdir) / "mlp.pt"
        mlp.save(save_path)
        assert save_path.exists()

        mlp2 = PyTorchMLPThreatModel(input_dim=14)
        mlp2.load(save_path)
        assert mlp2.is_fitted
        np.testing.assert_array_equal(preds[:5], ml2_preds := mlp2.predict(X[:5]))


def test_ensemble_soft_voting_and_weights(synthetic_training_data):
    X, y = synthetic_training_data
    ensemble = EnsembleThreatDetector(weights=(0.5, 0.3, 0.2))
    ensemble.fit(X, y)

    assert ensemble.is_fitted
    single_res = ensemble.predict_single(X[0])
    assert single_res["prediction"] in ["BENIGN", "MALICIOUS"]
    assert 0.0 <= single_res["confidence"] <= 1.0
    assert single_res["latency_ms"] >= 0.0
    assert "random_forest" in single_res["model_breakdown"]
    assert "xgboost" in single_res["model_breakdown"]
    assert "mlp" in single_res["model_breakdown"]

    labels, confs = ensemble.predict_batch(X[:20])
    assert len(labels) == 20
    assert len(confs) == 20
