from dataclasses import dataclass

import numpy as np

from backend.services.feature_engineering import feature_pipeline
from backend.services.synthetic_data import synthetic_generator
from ml.models.mlp import PyTorchMLPThreatModel


DOMAINS = ("HR", "Finance", "Engineering")


@dataclass
class FederatedSimulation:
    input_dim: int = 14

    def _domain_data(self, domain: str, samples: int) -> tuple[np.ndarray, np.ndarray]:
        scenarios = {
            "HR": "bruteforce",
            "Finance": "sqli",
            "Engineering": "portscan",
        }
        events = synthetic_generator.generate_batch(samples, scenarios[domain])
        benign = synthetic_generator.generate_batch(samples, "benign")
        records = events + benign
        X = np.asarray(
            [feature_pipeline.to_feature_vector(record) for record in records],
            dtype=np.float32,
        )
        y = np.asarray([1] * samples + [0] * samples, dtype=np.int64)
        return X, y

    def run(self, rounds: int = 20, samples_per_client: int = 20) -> dict:
        global_model = PyTorchMLPThreatModel(input_dim=self.input_dim)
        history = []
        for round_number in range(1, rounds + 1):
            client_parameters = []
            client_metrics = {}
            for domain in DOMAINS:
                X, y = self._domain_data(domain, samples_per_client)
                client = PyTorchMLPThreatModel(input_dim=self.input_dim)
                client.set_parameters(global_model.get_parameters())
                client.fit(X, y, epochs=1, batch_size=32)
                client_parameters.append((len(X), client.get_parameters()))
                accuracy = float(np.mean(client.predict(X) == y))
                client_metrics[domain] = {"samples": len(X), "accuracy": accuracy}

            total_samples = sum(count for count, _ in client_parameters)
            averaged = []
            for parameter_index in range(len(client_parameters[0][1])):
                averaged.append(
                    sum(
                        count * parameters[parameter_index]
                        for count, parameters in client_parameters
                    )
                    / total_samples
                )
            global_model.set_parameters(averaged)
            history.append(
                {
                    "round_number": round_number,
                    "num_clients": len(DOMAINS),
                    "client_metrics": client_metrics,
                    "global_metrics": {
                        "mean_client_accuracy": float(
                            np.mean([item["accuracy"] for item in client_metrics.values()])
                        )
                    },
                }
            )
        return {
            "rounds": rounds,
            "domains": list(DOMAINS),
            "aggregation_strategy": "FedAvg",
            "history": history,
        }


federated_simulation = FederatedSimulation()