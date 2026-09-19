import joblib
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier


class RandomForestThreatModel:
    """
    Random Forest Classifier for cyber-threat detection.
    Provides fast, robust tree-based baseline and inference.
    """

    def __init__(self, n_estimators: int = 100, max_depth: int = 15, random_state: int = 42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def save(self, filepath: Path):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, filepath)

    def load(self, filepath: Path):
        self.model = joblib.load(filepath)
        self.is_fitted = True
        return self
