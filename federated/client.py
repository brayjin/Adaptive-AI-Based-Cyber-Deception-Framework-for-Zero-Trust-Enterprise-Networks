from dataclasses import dataclass

import numpy as np

from ml.models.mlp import PyTorchMLPThreatModel


@dataclass
class FederatedClient:
    """Flower-compatible client contract without a hard Flower dependency."""

    domain: str
    model: PyTorchMLPThreatModel
    features: np.ndarray
    labels: np.ndarray

    def get_parameters(self) -> list[np.ndarray]:
        return self.model.get_parameters()

    def fit(self, parameters: list[np.ndarray]) -> tuple[list[np.ndarray], int, dict]:
        self.model.set_parameters(parameters)
        self.model.fit(self.features, self.labels, epochs=1, batch_size=32)
        accuracy = float(np.mean(self.model.predict(self.features) == self.labels))
        return self.model.get_parameters(), len(self.labels), {
            "domain": self.domain,
            "accuracy": accuracy,
        }

    def evaluate(self, parameters: list[np.ndarray]) -> tuple[float, int, dict]:
        self.model.set_parameters(parameters)
        predictions = self.model.predict(self.features)
        accuracy = float(np.mean(predictions == self.labels))
        return 1.0 - accuracy, len(self.labels), {"accuracy": accuracy}