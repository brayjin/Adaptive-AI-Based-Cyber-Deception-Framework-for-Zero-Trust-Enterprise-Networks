from pathlib import Path
from typing import OrderedDict
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset


class PyTorchMLPNet(nn.Module):
    def __init__(self, input_dim: int = 14, num_classes: int = 2):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class PyTorchMLPThreatModel:
    """
    PyTorch Multi-Layer Perceptron for threat detection.
    Supports gradient-based training and exposes parameter get/set
    compatible with Flower Federated Learning (FedAvg).
    """

    def __init__(self, input_dim: int = 14, num_classes: int = 2, lr: float = 0.001):
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.lr = lr
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = PyTorchMLPNet(input_dim=input_dim, num_classes=num_classes).to(self.device)
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int = 15, batch_size: int = 64):
        self.model.train()
        X_tensor = torch.tensor(X, dtype=torch.float32)
        y_tensor = torch.tensor(y, dtype=torch.long)
        dataset = TensorDataset(X_tensor, y_tensor)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=self.lr)

        for _ in range(epochs):
            for batch_x, batch_y in dataloader:
                batch_x, batch_y = batch_x.to(self.device), batch_y.to(self.device)
                optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()

        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        self.model.eval()
        X_tensor = torch.tensor(X, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            outputs = self.model(X_tensor)
            probs = torch.softmax(outputs, dim=1).cpu().numpy()
        return probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        probs = self.predict_proba(X)
        return np.argmax(probs, axis=1)

    # Federated Learning Helpers (Flower compatible)
    def get_parameters(self) -> list[np.ndarray]:
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]

    def set_parameters(self, parameters: list[np.ndarray]):
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
        self.model.load_state_dict(state_dict, strict=True)

    def save(self, filepath: Path):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), filepath)

    def load(self, filepath: Path):
        state_dict = torch.load(filepath, map_location=self.device)
        self.model.load_state_dict(state_dict)
        self.model.eval()
        self.is_fitted = True
        return self
