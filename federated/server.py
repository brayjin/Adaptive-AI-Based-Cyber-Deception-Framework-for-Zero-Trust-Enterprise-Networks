import numpy as np


class FedAvgServer:
    """Server-side weighted parameter aggregation compatible with Flower rounds."""

    @staticmethod
    def aggregate(
        client_results: list[tuple[list[np.ndarray], int, dict]],
    ) -> tuple[list[np.ndarray], dict]:
        if not client_results:
            raise ValueError("At least one client result is required")
        total_examples = sum(num_examples for _, num_examples, _ in client_results)
        parameters = []
        for index in range(len(client_results[0][0])):
            parameters.append(
                sum(
                    num_examples * result[0][index]
                    for result, num_examples, _ in client_results
                )
                / total_examples
            )
        metrics = {
            "num_clients": len(client_results),
            "num_examples": total_examples,
            "mean_accuracy": float(
                np.mean([result[2].get("accuracy", 0.0) for result in client_results])
            ),
        }
        return parameters, metrics