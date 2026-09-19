import math
from pydantic import BaseModel, Field
from backend.config import settings
from backend.models.events import NetworkEvent
from backend.models.predictions import ThreatPrediction
from backend.utils.logging import logger


class ZeroTrustPolicy(BaseModel):
    """
    Zero Trust continuous evaluation policy weights and decision thresholds.
    Configurable dynamically at runtime.
    """
    weight_identity: float = Field(0.20, ge=0.0, le=1.0)
    weight_device: float = Field(0.15, ge=0.0, le=1.0)
    weight_behaviour: float = Field(0.35, ge=0.0, le=1.0)
    weight_context: float = Field(0.15, ge=0.0, le=1.0)
    weight_network: float = Field(0.15, ge=0.0, le=1.0)

    threshold_allow: float = Field(0.20, ge=0.0, le=1.0)
    threshold_verify: float = Field(0.40, ge=0.0, le=1.0)
    threshold_restrict: float = Field(0.60, ge=0.0, le=1.0)
    threshold_deceive: float = Field(0.80, ge=0.0, le=1.0)

    def normalize_weights(self):
        total = (
            self.weight_identity
            + self.weight_device
            + self.weight_behaviour
            + self.weight_context
            + self.weight_network
        )
        if total > 0 and not math.isclose(total, 1.0, rel_tol=1e-3):
            self.weight_identity /= total
            self.weight_device /= total
            self.weight_behaviour /= total
            self.weight_context /= total
            self.weight_network /= total


class RiskScorer:
    """
    Multi-Factor Zero Trust Risk Scorer complying with NIST SP 800-207.
    Evaluates 5 independent risk dimensions to determine composite trust posture.
    """

    @staticmethod
    def calculate_identity_score(event_data: dict) -> float:
        """
        Calculates Identity Risk [0.0 - 1.0] based on failed logins, authentication
        state, and credential anomalies.
        """
        failed_logins = float(event_data.get("failed_login_count", 0))
        if failed_logins <= 0:
            return 0.05  # Baseline minimal ambient risk
        # Exponential escalation: 1 -> ~0.15, 5 -> ~0.55, 10+ -> ~0.85+
        score = 1.0 - math.exp(-0.18 * failed_logins)
        return min(1.0, max(0.0, float(score)))

    @staticmethod
    def calculate_device_score(event_data: dict) -> float:
        """
        Calculates Device Risk [0.0 - 1.0] based on destination port sensitivity,
        privileged service targeting, and host posture.
        """
        dest_port = int(event_data.get("dest_port", 80))
        score = 0.10

        # Privileged system ports (SSH, RDP, SMB, Telnet, DB)
        if dest_port in [22, 23, 445, 3389, 5985]:
            score += 0.45
        elif dest_port < 1024:
            score += 0.25

        # Check device metadata in raw_features if provided
        raw = event_data.get("raw_features", {})
        if raw.get("device_compliant") is False:
            score += 0.40
        if raw.get("unmanaged_device") is True:
            score += 0.30

        return min(1.0, max(0.0, float(score)))

    @staticmethod
    def calculate_behaviour_score(prediction_data: dict | None) -> float:
        """
        Calculates Behaviour Risk [0.0 - 1.0] driven by AI Threat Detection confidence.
        """
        if not prediction_data:
            return 0.20  # Neutral prior if no prediction available

        prediction = prediction_data.get("prediction", "BENIGN").upper()
        confidence = float(prediction_data.get("confidence", 0.5))

        if prediction == "MALICIOUS":
            # If AI is confident it is malicious, behaviour risk approaches 1.0
            return min(1.0, max(0.70, confidence))
        else:
            # If AI is confident it is benign, behaviour risk approaches 0.0
            return max(0.0, min(0.30, 1.0 - confidence))

    @staticmethod
    def calculate_context_score(event_data: dict) -> float:
        """
        Calculates Context Risk [0.0 - 1.0] based on access timing, duration, and frequency.
        """
        time_of_day = float(event_data.get("time_of_day", 0.5))
        duration = float(event_data.get("session_duration", 1.0))
        rate = float(event_data.get("connection_rate", 1.0))

        score = 0.10

        # Off-hours access (before 6 AM or after 9 PM)
        if time_of_day < 0.25 or time_of_day > 0.875:
            score += 0.30

        # Burst connection rate
        if rate > 20.0:
            score += 0.35
        elif rate > 5.0:
            score += 0.15

        # Extremely short burst session
        if duration < 0.1 and rate > 10.0:
            score += 0.20

        return min(1.0, max(0.0, float(score)))

    @staticmethod
    def calculate_network_score(event_data: dict) -> float:
        """
        Calculates Network Risk [0.0 - 1.0] based on port scan dispersion, byte ratio,
        and IP subnet characteristics.
        """
        port_div = float(event_data.get("port_diversity", 1))
        bytes_sent = float(event_data.get("bytes_sent", 0))
        bytes_recv = float(event_data.get("bytes_received", 0))
        packet_count = float(event_data.get("packet_count", 1))

        score = 0.10

        # Port scanning dispersion
        if port_div > 20:
            score += 0.55
        elif port_div > 5:
            score += 0.30

        # Massive packet flood
        if packet_count > 1000:
            score += 0.40

        # Exfiltration ratio (heavy outbound relative to inbound)
        if bytes_recv > 0 and (bytes_sent / (bytes_recv + 1.0)) > 50.0:
            score += 0.25

        return min(1.0, max(0.0, float(score)))

    def evaluate_composite_risk(
        self,
        event_data: dict,
        prediction_data: dict | None,
        policy: ZeroTrustPolicy,
    ) -> tuple[float, dict[str, float], str]:
        """
        Computes the composite risk score and maps it to a Zero Trust policy decision:
        ALLOW, VERIFY, RESTRICT, DECEIVE, BLOCK.
        """
        policy.normalize_weights()

        s_id = self.calculate_identity_score(event_data)
        s_dev = self.calculate_device_score(event_data)
        s_beh = self.calculate_behaviour_score(prediction_data)
        s_ctx = self.calculate_context_score(event_data)
        s_net = self.calculate_network_score(event_data)

        composite = (
            policy.weight_identity * s_id
            + policy.weight_device * s_dev
            + policy.weight_behaviour * s_beh
            + policy.weight_context * s_ctx
            + policy.weight_network * s_net
        )
        composite = min(1.0, max(0.0, composite))

        # Map to decision
        if composite < policy.threshold_allow:
            decision = "ALLOW"
        elif composite < policy.threshold_verify:
            decision = "VERIFY"
        elif composite < policy.threshold_restrict:
            decision = "RESTRICT"
        elif composite < policy.threshold_deceive:
            decision = "DECEIVE"
        else:
            decision = "BLOCK"

        scores = {
            "identity_score": round(s_id, 4),
            "device_score": round(s_dev, 4),
            "behaviour_score": round(s_beh, 4),
            "context_score": round(s_ctx, 4),
            "network_score": round(s_net, 4),
            "composite_risk_score": round(composite, 4),
        }

        return round(composite, 4), scores, decision


risk_scorer = RiskScorer()
