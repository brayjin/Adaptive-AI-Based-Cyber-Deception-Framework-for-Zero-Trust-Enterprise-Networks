import asyncio
import os
from pathlib import Path
import pandas as pd
from backend.services.synthetic_data import synthetic_generator
from backend.services.feature_engineering import feature_pipeline
from backend.config import settings
from backend.utils.logging import logger, setup_logging


def generate_benchmark_dataset(output_dir: Path, num_samples: int = 15000):
    """
    Generate a benchmark dataset with known ground-truth labels for offline
    training, cross-validation, and baseline testing.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging()
    logger.info("generating_benchmark_dataset", output_dir=str(output_dir), num_samples=num_samples)

    raw_events = synthetic_generator.generate_batch(count=num_samples, scenario="mixed")
    df_raw = pd.DataFrame(raw_events)
    
    # Extract ground truth label
    labels = [r["ground_truth_label"] for r in df_raw["raw_features"]]
    df_raw["label"] = labels
    
    # Save raw CSV
    raw_csv = output_dir / "benchmark_raw_events.csv"
    df_raw.to_csv(raw_csv, index=False)
    logger.info("saved_raw_dataset", path=str(raw_csv), rows=len(df_raw))

    # Generate feature-engineered dataset
    df_features = feature_pipeline.transform_dataframe(df_raw)
    df_features["label"] = labels
    df_features["is_attack"] = [0 if l == "BENIGN" else 1 for l in labels]
    
    feat_csv = output_dir / "benchmark_features.csv"
    df_features.to_csv(feat_csv, index=False)
    logger.info("saved_features_dataset", path=str(feat_csv), rows=len(df_features))

    return raw_csv, feat_csv


if __name__ == "__main__":
    out_path = Path("data/benchmark")
    generate_benchmark_dataset(out_path, num_samples=10000)
