import numpy as np
import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=PendingDeprecationWarning, module="shap")
    import shap
from backend.config import settings
from backend.utils.logging import logger


class ThreatExplainer:
    """
    Explainable AI (XAI) engine utilizing SHAP (SHapley Additive exPlanations)
    to compute feature contributions and generate natural-language rationale
    for threat predictions.
    """

    FEATURE_DESCRIPTIONS = {
        "dest_port": "Destination Port Target",
        "protocol_num": "Transport Protocol",
        "packet_count": "Packet Volume",
        "bytes_sent": "Outbound Payload Size",
        "bytes_received": "Inbound Payload Size",
        "connection_rate": "Connection Attempt Frequency",
        "failed_login_count": "Authentication Failure Count",
        "session_duration": "Flow Session Duration",
        "bytes_ratio": "Asymmetric Byte Ratio",
        "port_diversity": "Port Scan Dispersion Index",
        "time_of_day": "Temporal Access Window",
        "is_privileged_port": "Privileged System Port Access",
        "connection_frequency": "Normalized Connection Rate",
        "packets_per_second": "Flow Packet Velocity",
    }

    def __init__(self, feature_names: list[str] | None = None):
        self.feature_names = feature_names or settings.FEATURE_NAMES
        self.explainer = None
        self.is_initialized = False

    def initialize_with_model(self, model, background_data: np.ndarray | None = None):
        """
        Initialize SHAP TreeExplainer with a fitted model (e.g. XGBoost or Random Forest).
        """
        try:
            # Handle wrapper or raw model
            raw_model = getattr(model, "model", model)
            if background_data is not None and len(background_data) > 100:
                # Sample background data for computational efficiency
                sample_idx = np.random.choice(len(background_data), size=min(100, len(background_data)), replace=False)
                bg_sample = background_data[sample_idx]
                self.explainer = shap.TreeExplainer(raw_model, data=bg_sample)
            else:
                self.explainer = shap.TreeExplainer(raw_model)
            self.is_initialized = True
            logger.info("shap_explainer_initialized")
        except Exception as e:
            logger.warning("shap_initialization_fallback", error=str(e))
            self.explainer = None
            self.is_initialized = False

    def explain_instance(
        self,
        feature_vector: np.ndarray,
        prediction: str,
        confidence: float,
    ) -> dict:
        """
        Compute feature contributions for a single instance and generate
        human-readable explanations.
        """
        X = np.expand_dims(feature_vector, axis=0)

        # Fallback heuristic explanation if explainer is not initialized or fails
        if not self.is_initialized or self.explainer is None:
            return self._heuristic_explanation(feature_vector, prediction, confidence)

        try:
            shap_values = self.explainer.shap_values(X)

            # TreeExplainer output handling: could be a list (multi-class) or 2D array
            if isinstance(shap_values, list):
                # For binary classification, use index 1 (malicious class)
                vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
            elif hasattr(shap_values, "values"):
                # Explanation object
                vals = shap_values.values[0]
                if vals.ndim > 1:
                    vals = vals[:, 1]
            elif shap_values.ndim == 2:
                vals = shap_values[0]
            else:
                vals = shap_values

            return self._format_contributions(vals, feature_vector, prediction, confidence)

        except Exception as e:
            logger.warning("shap_computation_failed_using_fallback", error=str(e))
            return self._heuristic_explanation(feature_vector, prediction, confidence)

    def _format_contributions(
        self,
        shap_vals: np.ndarray,
        feature_vector: np.ndarray,
        prediction: str,
        confidence: float,
    ) -> dict:
        contributions = []
        for i, name in enumerate(self.feature_names):
            val = float(shap_vals[i]) if i < len(shap_vals) else 0.0
            feat_val = float(feature_vector[i]) if i < len(feature_vector) else 0.0
            contributions.append({
                "feature": name,
                "display_name": self.FEATURE_DESCRIPTIONS.get(name, name),
                "value": feat_val,
                "contribution": round(val, 4),
                "abs_contribution": abs(val),
                "direction": "positive" if val > 0 else "negative",
            })

        # Sort by absolute importance
        contributions.sort(key=lambda x: x["abs_contribution"], reverse=True)
        top_factors = contributions[:5]

        # Natural-language synthesis
        narrative = self._generate_narrative(top_factors, prediction, confidence)

        return {
            "prediction": prediction,
            "confidence": confidence,
            "top_features": top_factors,
            "all_contributions": {c["feature"]: c["contribution"] for c in contributions},
            "explanation": narrative,
        }

    def _generate_narrative(
        self,
        top_factors: list[dict],
        prediction: str,
        confidence: float,
    ) -> str:
        conf_pct = f"{confidence * 100:.1f}%"
        if prediction == "MALICIOUS":
            driver_phrases = []
            for f in top_factors:
                if f["direction"] == "positive":
                    if f["feature"] == "failed_login_count" and f["value"] > 0:
                        driver_phrases.append(f"repeated authentication failures ({int(f['value'])} attempts)")
                    elif f["feature"] == "connection_rate" and f["value"] > 5.0:
                        driver_phrases.append(f"abnormally rapid connection frequency ({f['value']:.1f} conn/s)")
                    elif f["feature"] == "port_diversity" and f["value"] > 5:
                        driver_phrases.append(f"scanning across multiple distinct destination ports ({int(f['value'])} ports)")
                    elif f["feature"] == "packets_per_second" and f["value"] > 100:
                        driver_phrases.append(f"high flow packet velocity ({f['value']:.0f} pkts/s)")
                    elif f["feature"] == "bytes_ratio" and f["value"] > 5.0:
                        driver_phrases.append(f"asymmetric outbound data volume ({f['value']:.1f} ratio)")
                    else:
                        driver_phrases.append(f"elevated {f['display_name']}")

            if driver_phrases:
                drivers_str = "; ".join(driver_phrases[:3])
                narrative = (
                    f"Classified as MALICIOUS with {conf_pct} confidence. "
                    f"Primary risk drivers: {drivers_str}. "
                    f"Action required: Escalated to Zero Trust continuous risk evaluation."
                )
            else:
                narrative = (
                    f"Classified as MALICIOUS with {conf_pct} confidence based on correlated behavioural anomalies. "
                    f"Action required: Continuous Zero Trust re-evaluation."
                )
        else:
            narrative = (
                f"Classified as BENIGN with {conf_pct} confidence. "
                f"Flow metrics conform to established baseline traffic characteristics."
            )

        return narrative

    def _heuristic_explanation(
        self,
        feature_vector: np.ndarray,
        prediction: str,
        confidence: float,
    ) -> dict:
        """
        Fast heuristic explanation when SHAP explainer is loading or unavailable.
        """
        contributions = []
        for i, name in enumerate(self.feature_names):
            val = float(feature_vector[i]) if i < len(feature_vector) else 0.0
            
            # Heuristic weights
            weight = 0.0
            if name == "failed_login_count" and val > 0:
                weight = min(0.40, val * 0.05)
            elif name == "connection_rate" and val > 10:
                weight = min(0.30, val * 0.01)
            elif name == "port_diversity" and val > 5:
                weight = min(0.25, val * 0.02)
            elif name == "packets_per_second" and val > 500:
                weight = 0.25
            elif name == "session_duration" and val > 20:
                weight = -0.10  # Long duration usually indicates benign
            
            if prediction != "MALICIOUS":
                weight = -abs(weight) if weight > 0 else 0.1

            contributions.append({
                "feature": name,
                "display_name": self.FEATURE_DESCRIPTIONS.get(name, name),
                "value": val,
                "contribution": round(weight, 4),
                "abs_contribution": abs(weight),
                "direction": "positive" if weight > 0 else "negative",
            })

        contributions.sort(key=lambda x: x["abs_contribution"], reverse=True)
        top_factors = contributions[:5]
        narrative = self._generate_narrative(top_factors, prediction, confidence)

        return {
            "prediction": prediction,
            "confidence": confidence,
            "top_features": top_factors,
            "all_contributions": {c["feature"]: c["contribution"] for c in contributions},
            "explanation": narrative,
        }


threat_explainer = ThreatExplainer()
