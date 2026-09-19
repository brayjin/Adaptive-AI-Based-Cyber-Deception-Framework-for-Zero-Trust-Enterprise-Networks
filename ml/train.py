import json
import sys
import time
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
from backend.config import settings
from backend.utils.logging import logger, setup_logging
from ml.models.random_forest import RandomForestThreatModel
from ml.models.xgboost_model import XGBoostThreatModel
from ml.models.mlp import PyTorchMLPThreatModel
from ml.models.ensemble import EnsembleThreatDetector
from ml.explainability.shap_explainer import threat_explainer


def evaluate_model_performance(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    inference_time_ms: float,
    model_name: str,
) -> dict:
    cm = confusion_matrix(y_true, y_pred)
    # Binary classification confusion matrix: [[TN, FP], [FN, TP]]
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    else:
        fpr, fnr = 0.0, 0.0

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    
    try:
        auc = float(roc_auc_score(y_true, y_proba[:, 1] if y_proba.ndim > 1 else y_proba))
    except Exception:
        auc = 0.5

    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)

    metrics = {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "latency_ms": round(inference_time_ms, 3),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
    }
    return metrics


def train_and_evaluate(
    data_csv: Path | None = None,
    save_dir: Path | None = None,
    sample_size: int = 10000,
) -> dict:
    setup_logging()
    data_csv = data_csv or (settings.BASE_DIR / "data" / "benchmark" / "benchmark_features.csv")
    save_dir = save_dir or settings.SAVED_MODELS_DIR
    save_dir.mkdir(parents=True, exist_ok=True)

    # Ensure dataset exists
    if not data_csv.exists():
        logger.info("benchmark_dataset_not_found_generating", path=str(data_csv))
        from scripts.download_dataset import generate_benchmark_dataset
        generate_benchmark_dataset(data_csv.parent, num_samples=sample_size)

    logger.info("loading_training_dataset", path=str(data_csv))
    df = pd.read_csv(data_csv)

    feature_cols = settings.FEATURE_NAMES
    X = df[feature_cols].values.astype(np.float32)
    y = df["is_attack"].values.astype(np.int64)

    # Stratified Split: 70% train, 15% val, 15% test
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    logger.info(
        "dataset_split_complete",
        train_samples=len(X_train),
        val_samples=len(X_val),
        test_samples=len(X_test),
        attack_ratio=float(np.mean(y)),
    )

    all_metrics = {}

    # 1. Random Forest
    logger.info("training_model", model="RandomForest")
    rf = RandomForestThreatModel()
    start = time.perf_counter()
    rf.fit(X_train, y_train)
    rf_train_time = time.perf_counter() - start

    start = time.perf_counter()
    rf_preds = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)
    rf_latency = (time.perf_counter() - start) * 1000.0 / len(X_test)
    all_metrics["RandomForest"] = evaluate_model_performance(
        y_test, rf_preds, rf_proba, rf_latency, "RandomForest"
    )

    # 2. XGBoost
    logger.info("training_model", model="XGBoost")
    xgb = XGBoostThreatModel()
    start = time.perf_counter()
    xgb.fit(X_train, y_train)
    xgb_train_time = time.perf_counter() - start

    start = time.perf_counter()
    xgb_preds = xgb.predict(X_test)
    xgb_proba = xgb.predict_proba(X_test)
    xgb_latency = (time.perf_counter() - start) * 1000.0 / len(X_test)
    all_metrics["XGBoost"] = evaluate_model_performance(
        y_test, xgb_preds, xgb_proba, xgb_latency, "XGBoost"
    )

    # 3. PyTorch MLP
    logger.info("training_model", model="PyTorch_MLP")
    mlp = PyTorchMLPThreatModel(input_dim=len(feature_cols))
    start = time.perf_counter()
    mlp.fit(X_train, y_train, epochs=15)
    mlp_train_time = time.perf_counter() - start

    start = time.perf_counter()
    mlp_preds = mlp.predict(X_test)
    mlp_proba = mlp.predict_proba(X_test)
    mlp_latency = (time.perf_counter() - start) * 1000.0 / len(X_test)
    all_metrics["PyTorch_MLP"] = evaluate_model_performance(
        y_test, mlp_preds, mlp_proba, mlp_latency, "PyTorch_MLP"
    )

    # 4. Weighted Ensemble
    logger.info("evaluating_model", model="Ensemble")
    ensemble = EnsembleThreatDetector()
    ensemble.rf = rf
    ensemble.xgb = xgb
    ensemble.mlp = mlp
    ensemble.is_fitted = True

    start = time.perf_counter()
    ens_preds, ens_conf = ensemble.predict_batch(X_test)
    ens_latency = (time.perf_counter() - start) * 1000.0 / len(X_test)
    
    # Calculate probabilities for ensemble
    ens_proba = (
        0.40 * rf_proba + 0.40 * xgb_proba + 0.20 * mlp_proba
    )
    all_metrics["Ensemble"] = evaluate_model_performance(
        y_test, ens_preds, ens_proba, ens_latency, "Ensemble"
    )

    # 5. Initialize SHAP with the trained XGBoost model
    logger.info("initializing_shap_explainer")
    threat_explainer.initialize_with_model(xgb.model, background_data=X_train)

    # Save models
    ensemble.save(save_dir)
    metrics_path = save_dir / "evaluation_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(all_metrics, f, indent=2)

    logger.info(
        "training_and_evaluation_complete",
        saved_dir=str(save_dir),
        ensemble_f1=all_metrics["Ensemble"]["f1_score"],
        ensemble_auc=all_metrics["Ensemble"]["roc_auc"],
    )

    return all_metrics


if __name__ == "__main__":
    metrics = train_and_evaluate()
    print("\n" + "=" * 80)
    print("MODEL PERFORMANCE EVALUATION SUMMARY")
    print("=" * 80)
    for model_name, m in metrics.items():
        print(
            f"{model_name:<15} | Acc: {m['accuracy']:.4f} | Prec: {m['precision']:.4f} | "
            f"Rec: {m['recall']:.4f} | F1: {m['f1_score']:.4f} | AUC: {m['roc_auc']:.4f} | "
            f"FPR: {m['fpr']:.4f} | Latency: {m['latency_ms']:.3f}ms"
        )
    print("=" * 80 + "\n")
