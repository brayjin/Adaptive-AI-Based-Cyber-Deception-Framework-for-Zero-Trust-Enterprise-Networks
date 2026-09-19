import numpy as np
import pytest
from ml.explainability.shap_explainer import ThreatExplainer
from ml.models.random_forest import RandomForestThreatModel


@pytest.fixture
def fitted_rf_model():
    np.random.seed(42)
    X = np.random.randn(100, 14).astype(np.float32)
    # Feature 6 (failed_login_count) strongly predicts 1
    y = (X[:, 6] > 0.5).astype(np.int64)
    rf = RandomForestThreatModel(n_estimators=10, max_depth=4)
    rf.fit(X, y)
    return rf, X


def test_explainer_heuristic_fallback():
    explainer = ThreatExplainer()
    # Uninitialized explainer should automatically use heuristic fallback
    vec = np.zeros(14, dtype=np.float32)
    vec[6] = 20.0  # 20 failed logins
    
    res = explainer.explain_instance(vec, prediction="MALICIOUS", confidence=0.95)
    assert res["prediction"] == "MALICIOUS"
    assert res["confidence"] == 0.95
    assert len(res["top_features"]) <= 5
    assert "explanation" in res
    assert len(res["explanation"]) > 20
    assert "repeated authentication failures" in res["explanation"] or "failed_login_count" in str(res["top_features"])


def test_explainer_with_tree_model(fitted_rf_model):
    rf, X = fitted_rf_model
    explainer = ThreatExplainer()
    explainer.initialize_with_model(rf.model, background_data=X[:30])
    
    assert explainer.is_initialized
    test_vec = X[0]
    res = explainer.explain_instance(test_vec, prediction="MALICIOUS", confidence=0.88)
    
    assert res["prediction"] == "MALICIOUS"
    assert len(res["top_features"]) <= 5
    assert "explanation" in res
    for feat in res["top_features"]:
        assert "feature" in feat
        assert "contribution" in feat
        assert "direction" in feat
        assert feat["direction"] in ["positive", "negative"]


def test_explainer_benign_narrative():
    explainer = ThreatExplainer()
    vec = np.zeros(14, dtype=np.float32)
    res = explainer.explain_instance(vec, prediction="BENIGN", confidence=0.98)
    assert "BENIGN" in res["explanation"]
    assert "baseline traffic" in res["explanation"] or "Classified as BENIGN" in res["explanation"]
