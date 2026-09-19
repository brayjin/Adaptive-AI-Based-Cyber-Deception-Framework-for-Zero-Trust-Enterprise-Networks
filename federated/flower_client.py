import flwr as fl
import numpy as np

from federated.client import FederatedClient


class FlowerMLPClient(fl.client.NumPyClient):
    """Flower adapter for a local PyTorch MLP client."""

    def __init__(self, client: FederatedClient):
        self.client = client

    def get_parameters(self, config):
        return self.client.get_parameters()

    def fit(self, parameters, config):
        updated, count, metrics = self.client.fit(parameters)
        return updated, count, metrics

    def evaluate(self, parameters, config):
        loss, count, metrics = self.client.evaluate(parameters)
        return float(loss), count, metrics

    def to_client(self):
        return self


def fedavg_strategy() -> fl.server.strategy.FedAvg:
    return fl.server.strategy.FedAvg(
        fraction_fit=1.0,
        fraction_evaluate=1.0,
        min_fit_clients=3,
        min_evaluate_clients=3,
        min_available_clients=3,
    )