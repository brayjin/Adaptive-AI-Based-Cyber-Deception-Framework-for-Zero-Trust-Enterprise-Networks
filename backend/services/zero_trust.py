from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.config import settings
from backend.models.events import NetworkEvent
from backend.models.predictions import ThreatPrediction
from backend.models.evaluations import ZeroTrustEvaluation
from backend.services.risk_scorer import ZeroTrustPolicy, risk_scorer
from backend.services.threat_detector import threat_detector_service
from backend.utils.logging import logger


class ZeroTrustEngine:
    """
    Zero Trust continuous evaluation engine.
    Applies continuous trust assessment, computing composite risk and deciding
    ALLOW, VERIFY, RESTRICT, DECEIVE, or BLOCK.
    """

    def __init__(self):
        self.policy = ZeroTrustPolicy(
            weight_identity=settings.ZT_WEIGHT_IDENTITY,
            weight_device=settings.ZT_WEIGHT_DEVICE,
            weight_behaviour=settings.ZT_WEIGHT_BEHAVIOUR,
            weight_context=settings.ZT_WEIGHT_CONTEXT,
            weight_network=settings.ZT_WEIGHT_NETWORK,
            threshold_allow=settings.ZT_THRESHOLD_ALLOW,
            threshold_verify=settings.ZT_THRESHOLD_VERIFY,
            threshold_restrict=settings.ZT_THRESHOLD_RESTRICT,
            threshold_deceive=settings.ZT_THRESHOLD_DECEIVE,
        )

    def get_policy(self) -> ZeroTrustPolicy:
        return self.policy

    def update_policy(self, updated_policy: ZeroTrustPolicy) -> ZeroTrustPolicy:
        updated_policy.normalize_weights()
        self.policy = updated_policy
        logger.info(
            "zero_trust_policy_updated",
            weights={
                "id": self.policy.weight_identity,
                "dev": self.policy.weight_device,
                "beh": self.policy.weight_behaviour,
                "ctx": self.policy.weight_context,
                "net": self.policy.weight_network,
            },
            thresholds={
                "allow": self.policy.threshold_allow,
                "verify": self.policy.threshold_verify,
                "restrict": self.policy.threshold_restrict,
                "deceive": self.policy.threshold_deceive,
            },
        )
        return self.policy

    async def evaluate_event(
        self,
        db: AsyncSession,
        event: NetworkEvent,
        prediction: ThreatPrediction | None = None,
    ) -> ZeroTrustEvaluation:
        """
        Evaluate trust for a given NetworkEvent and optional ThreatPrediction.
        If prediction is not provided, trigger AI detection automatically.
        """
        if prediction is None:
            # Automatic continuous evaluation: obtain prediction first
            prediction = await threat_detector_service.detect_and_record(db, event)

        event_data = {
            "source_ip": event.source_ip,
            "dest_ip": event.dest_ip,
            "source_port": event.source_port,
            "dest_port": event.dest_port,
            "protocol": event.protocol,
            "packet_count": event.packet_count,
            "bytes_sent": event.bytes_sent,
            "bytes_received": event.bytes_received,
            "connection_rate": event.connection_rate,
            "failed_login_count": event.failed_login_count,
            "session_duration": event.session_duration,
            "raw_features": event.raw_features or {},
        }

        pred_data = {
            "prediction": prediction.prediction,
            "confidence": prediction.confidence,
        }

        composite_score, factor_scores, decision = risk_scorer.evaluate_composite_risk(
            event_data=event_data,
            prediction_data=pred_data,
            policy=self.policy,
        )

        evaluation = ZeroTrustEvaluation(
            event_id=event.id,
            prediction_id=prediction.id,
            identity_score=factor_scores["identity_score"],
            device_score=factor_scores["device_score"],
            behaviour_score=factor_scores["behaviour_score"],
            context_score=factor_scores["context_score"],
            network_score=factor_scores["network_score"],
            composite_risk_score=composite_score,
            trust_decision=decision,
            evaluation_details={
                "policy_weights": {
                    "identity": self.policy.weight_identity,
                    "device": self.policy.weight_device,
                    "behaviour": self.policy.weight_behaviour,
                    "context": self.policy.weight_context,
                    "network": self.policy.weight_network,
                },
                "thresholds": {
                    "allow": self.policy.threshold_allow,
                    "verify": self.policy.threshold_verify,
                    "restrict": self.policy.threshold_restrict,
                    "deceive": self.policy.threshold_deceive,
                },
                "prediction_label": prediction.prediction,
                "prediction_confidence": prediction.confidence,
            },
        )

        db.add(evaluation)
        await db.flush()

        logger.info(
            "zero_trust_evaluation_completed",
            event_id=event.id,
            decision=decision,
            composite_risk=composite_score,
            factors=factor_scores,
        )
        return evaluation


zero_trust_engine = ZeroTrustEngine()
