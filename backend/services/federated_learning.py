from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from backend.config import settings
from backend.services.feature_engineering import feature_pipeline
from backend.services.synthetic_data import synthetic_generator
from ml.models.mlp import PyTorchMLPThreatModel


@dataclass
class FederatedSimulation:
    input_dim: int = 14
    domains: tuple = field(default=("HR", "Finance", "Engineering"))
    _held_out: tuple = field(default=None, init=False, repr=False)

    def _domain_data(self, domain: str, samples: int, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
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

    def _held_out_data(self, samples: int = 120, seed: int = 99) -> tuple[np.ndarray, np.ndarray]:
        if self._held_out is not None:
            return self._held_out
        events = synthetic_generator.generate_batch(samples // 2, "mixed")
        benign = synthetic_generator.generate_batch(samples // 2, "benign")
        records = events + benign
        X = np.asarray(
            [feature_pipeline.to_feature_vector(record) for record in records],
            dtype=np.float32,
        )
        labels = []
        for record in records:
            raw = record.get("raw_features", {})
            label = raw.get("ground_truth_label", "BENIGN") if isinstance(raw, dict) else "BENIGN"
            labels.append(0 if label == "BENIGN" else 1)
        y = np.asarray(labels, dtype=np.int64)
        self._held_out = (X, y)
        return self._held_out

    def run(self, rounds: int = 20, samples_per_client: int = 20, seed: int = 42) -> dict:
        global_model = PyTorchMLPThreatModel(input_dim=self.input_dim)
        X_hold, y_hold = self._held_out_data()
        history = []
        for round_number in range(1, rounds + 1):
            client_parameters = []
            client_metrics = {}
            round_seed = seed + round_number
            for domain_index, domain in enumerate(self.domains):
                X, y = self._domain_data(domain, samples_per_client, seed=round_seed + domain_index)
                client = PyTorchMLPThreatModel(input_dim=self.input_dim)
                client.set_parameters(global_model.get_parameters())
                client.fit(X, y, epochs=1, batch_size=32)
                client_parameters.append((len(X), client.get_parameters()))
                train_accuracy = float(np.mean(client.predict(X) == y))
                client_metrics[domain] = {
                    "samples": len(X),
                    "train_accuracy": train_accuracy,
                }

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

            global_train_accuracy = float(
                np.mean([m["train_accuracy"] for m in client_metrics.values()])
            )
            global_held_out_accuracy = float(
                np.mean(global_model.predict(X_hold) == y_hold)
            )
            history.append(
                {
                    "round_number": round_number,
                    "num_clients": len(self.domains),
                    "client_metrics": client_metrics,
                    "global_metrics": {
                        "mean_client_train_accuracy": global_train_accuracy,
                        "held_out_accuracy": global_held_out_accuracy,
                    },
                }
            )

        artifact_path = settings.SAVED_MODELS_DIR / "federated_global.pt"
        global_model.save(artifact_path)

        loaded_model = PyTorchMLPThreatModel(input_dim=self.input_dim)
        loaded_model.load(artifact_path)
        loaded_accuracy = float(np.mean(loaded_model.predict(X_hold) == y_hold))

        centralized_accuracy = self._centralized_accuracy(
            samples_per_client, rounds, seed, X_hold, y_hold
        )

        return {
            "rounds": rounds,
            "domains": list(self.domains),
            "aggregation_strategy": "FedAvg",
            "history": history,
            "final_held_out_accuracy": global_held_out_accuracy,
            "centralized_held_out_accuracy": centralized_accuracy,
            "artifact_path": str(artifact_path),
            "model_load_verified": True,
            "loaded_model_held_out_accuracy": loaded_accuracy,
        }

    def _centralized_accuracy(self, samples_per_client, epochs, seed, X_hold, y_hold) -> float:
        X_parts = []
        y_parts = []
        for domain_index, domain in enumerate(self.domains):
            X, y = self._domain_data(domain, samples_per_client, seed=seed + domain_index)
            X_parts.append(X)
            y_parts.append(y)
        X_all = np.concatenate(X_parts, axis=0)
        y_all = np.concatenate(y_parts, axis=0)
        model = PyTorchMLPThreatModel(input_dim=self.input_dim)
        model.fit(X_all, y_all, epochs=max(1, epochs), batch_size=32)
        return float(np.mean(model.predict(X_hold) == y_hold))


federated_simulation = FederatedSimulation()


def run_flower_simulation(rounds: int = 3, samples_per_client: int = 20):
    """Optional Flower-based workflow; returns status without affecting NumPy baseline."""
    try:
        import flwr as fl
    except Exception as exc:  # pragma: no cover - dependency optional
        return {"status": "UNAVAILABLE", "reason": str(exc)}

    # Flower execution is intentionally not invoked here by default because it
    # requires a running simulation environment and client processes. The
    # existing NumPy baseline remains the primary, verified implementation.
    return {
        "status": "AVAILABLE_NOT_EXECUTED",
        "rounds_requested": rounds,
        "samples_per_client": samples_per_client,
        "note": "Call flwr.simulation.start_simulation with federated.flower_client to execute.",
    }
