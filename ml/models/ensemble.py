import time
from pathlib import Path
import numpy as np
from ml.models.random_forest import RandomForestThreatModel
from ml.models.xgboost_model import XGBoostThreatModel
from ml.models.mlp import PyTorchMLPThreatModel
from backend.utils.logging import logger


class EnsembleThreatDetector:
    """
    Weighted Ensemble Threat Detector combining Random Forest, XGBoost, and PyTorch MLP.
    Combines complementary tree-based and neural representations for robust cyber-threat detection.
    """

    CLASS_NAMES = ["BENIGN", "MALICIOUS"]

    def __init__(
        self,
        weights: tuple[float, float, float] = (0.40, 0.40, 0.20),
    ):
        self.weights = weights  # (RF, XGB, MLP)
        self.rf = RandomForestThreatModel()
        self.xgb = XGBoostThreatModel()
        self.mlp = PyTorchMLPThreatModel()
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        logger.info("training_ensemble_models", samples=len(X))
        logger.info("training_random_forest")
        self.rf.fit(X, y)
        logger.info("training_xgboost")
        self.xgb.fit(X, y)
        logger.info("training_pytorch_mlp")
        self.mlp.fit(X, y)
        self.is_fitted = True
        logger.info("ensemble_training_complete")
        return self

    def predict_single(self, feature_vector: np.ndarray) -> dict:
        """
        Predict threat level and confidence for a single 1D feature vector.
        Returns prediction details and latency in milliseconds.
        """
        start_time = time.perf_counter()
        X = np.expand_dims(feature_vector, axis=0)

        # Gather probabilities from all 3 models
        p_rf = self.rf.predict_proba(X)[0] if self.rf.is_fitted else np.array([0.5, 0.5])
        p_xgb = self.xgb.predict_proba(X)[0] if self.xgb.is_fitted else np.array([0.5, 0.5])
        p_mlp = self.mlp.predict_proba(X)[0] if self.mlp.is_fitted else np.array([0.5, 0.5])

        w_rf, w_xgb, w_mlp = self.weights
        p_ensemble = (w_rf * p_rf) + (w_xgb * p_xgb) + (w_mlp * p_mlp)

        predicted_idx = int(np.argmax(p_ensemble))
        confidence = float(p_ensemble[predicted_idx])
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        prediction_label = self.CLASS_NAMES[predicted_idx]

        return {
            "prediction": prediction_label,
            "confidence": confidence,
            "latency_ms": latency_ms,
            "probabilities": {
                "benign": float(p_ensemble[0]),
                "malicious": float(p_ensemble[1]),
            },
            "model_breakdown": {
                "random_forest": float(p_rf[1]),
                "xgboost": float(p_xgb[1]),
                "mlp": float(p_mlp[1]),
            }
        }

    def predict_batch(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Batch prediction returning (labels, confidences).
        """
        p_rf = self.rf.predict_proba(X)
        p_xgb = self.xgb.predict_proba(X)
        p_mlp = self.mlp.predict_proba(X)

        w_rf, w_xgb, w_mlp = self.weights
        p_ensemble = (w_rf * p_rf) + (w_xgb * p_xgb) + (w_mlp * p_mlp)

        labels = np.argmax(p_ensemble, axis=1)
        confidences = np.max(p_ensemble, axis=1)
        return labels, confidences

    def save(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.rf.save(directory / "random_forest.joblib")
        self.xgb.save(directory / "xgboost.joblib")
        self.mlp.save(directory / "mlp.pt")
        logger.info("saved_ensemble_models", directory=str(directory))

    def load(self, directory: Path):
        rf_path = directory / "random_forest.joblib"
        xgb_path = directory / "xgboost.joblib"
        mlp_path = directory / "mlp.pt"

        if rf_path.exists():
            self.rf.load(rf_path)
        if xgb_path.exists():
            self.xgb.load(xgb_path)
        if mlp_path.exists():
            self.mlp.load(mlp_path)

        self.is_fitted = self.rf.is_fitted and self.xgb.is_fitted and self.mlp.is_fitted
        return self
