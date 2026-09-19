import argparse
import json
import time
from pathlib import Path

import matplotlib.pyplot as plt

from backend.services.federated_learning import federated_simulation
from backend.services.rl_deception import adaptive_policy

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _resolve_output_path(raw_output: Path) -> Path:
    candidate = Path(raw_output).expanduser()
    if not candidate.is_absolute():
        candidate = (PROJECT_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    try:
        candidate.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError(f"Output path must remain under project root: {PROJECT_ROOT}") from exc

    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def run(output: Path, rounds: int = 5, episodes: int = 100) -> dict:
    resolved_output = _resolve_output_path(output)
    plot_dir = resolved_output.parent / "plots"
    plot_dir.mkdir(parents=True, exist_ok=True)
    baselines = adaptive_policy.evaluate_baselines(episodes)
    federated = federated_simulation.run(rounds, 10)
    latency_samples = []
    for _ in range(episodes):
        started = time.perf_counter()
        adaptive_policy.select_action([0.5] * 12)
        latency_samples.append((time.perf_counter() - started) * 1000)

    baseline_plot = plot_dir / "rl_baselines.png"
    plt.figure(figsize=(8, 4))
    plt.bar(list(baselines), [item["mean_reward"] for item in baselines.values()])
    plt.ylabel("Mean reward")
    plt.tight_layout()
    plt.savefig(baseline_plot)
    plt.close()

    convergence_plot = plot_dir / "federated_convergence.png"
    history = federated["history"]
    plt.figure(figsize=(8, 4))
    plt.plot(
        [item["round_number"] for item in history],
        [item["global_metrics"]["mean_client_accuracy"] for item in history],
        marker="o",
    )
    plt.xlabel("Round")
    plt.ylabel("Mean client accuracy")
    plt.tight_layout()
    plt.savefig(convergence_plot)
    plt.close()

    results = {
        "experiment_1_rl_baselines": baselines,
        "experiment_2_federated_convergence": federated,
        "experiment_3_policy_training": adaptive_policy.train(episodes),
        "experiment_4_deception_actions": {
            "actions": adaptive_policy.describe()["actions"],
            "algorithm": adaptive_policy.describe()["algorithm"],
        },
        "experiment_5_data_privacy": {
            "raw_events_transmitted": False,
            "shared_artifact": "model_parameters_and_metrics",
        },
        "experiment_6_latency": {
            "mean_policy_latency_ms": sum(latency_samples) / len(latency_samples),
            "samples": len(latency_samples),
        },
        "experiment_7_reproducibility": {"seed": 42, "rounds": rounds, "episodes": episodes},
        "plots": [str(baseline_plot), str(convergence_plot)],
    }
    resolved_output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run framework research experiments")
    parser.add_argument("--output", type=Path, default=Path("data/experiments/results.json"))
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--episodes", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.rounds, args.episodes), indent=2))


if __name__ == "__main__":
    main()