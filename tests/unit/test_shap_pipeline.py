import numpy as np
import pytest

from ml.explainability.shap_explainer import ThreatExplainer
from ml.models.xgboost_model import XGBoostThreatModel


@pytest.fixture
def fitted_xgb():
    np.random.seed(7)
    X = np.random.randn(120, 14).astype(np.float32)
    y = (X[:, 6] > 0.3).astype(np.int64)
    model = XGBoostThreatModel(n_estimators=20, max_depth=3)
    model.fit(X, y)
    return model, X


def test_shap_uses_trained_xgboost_and_preserves_values(fitted_xgb):
    model, X = fitted_xgb
    explainer = ThreatExplainer()
    explainer.initialize_with_model(model.model, background_data=X[:20])
    assert explainer.is_initialized

    vec = X[5]
    result = explainer.explain_instance(vec, prediction="MALICIOUS", confidence=0.9)
    assert result["prediction"] == "MALICIOUS"
    assert len(result["top_features"]) == 5
    for feat in result["top_features"]:
        assert "contribution" in feat
        assert feat["direction"] in ["positive", "negative"]
    # all 14 contributions present
    assert len(result["all_contributions"]) == 14


def test_shap_benign_event(fitted_xgb):
    model, X = fitted_xgb
    explainer = ThreatExplainer()
    explainer.initialize_with_model(model.model, background_data=X[:20])
    vec = np.zeros(14, dtype=np.float32)
    result = explainer.explain_instance(vec, prediction="BENIGN", confidence=0.98)
    assert "BENIGN" in result["explanation"]
    assert len(result["top_features"]) <= 5


def test_shap_failure_does_not_change_prediction():
    # Uninitialized explainer must fall back without raising
    explainer = ThreatExplainer()
    vec = np.ones(14, dtype=np.float32)
    result = explainer.explain_instance(vec, prediction="MALICIOUS", confidence=0.8)
    assert result["prediction"] == "MALICIOUS"
    assert "explanation" in result
