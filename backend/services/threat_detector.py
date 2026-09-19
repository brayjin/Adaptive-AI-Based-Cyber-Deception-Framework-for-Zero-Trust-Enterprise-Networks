import time
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from backend.config import settings
from backend.models.events import NetworkEvent
from backend.models.predictions import ThreatPrediction
from backend.services.feature_engineering import feature_pipeline
from backend.utils.logging import logger
from ml.models.ensemble import EnsembleThreatDetector
from ml.explainability.shap_explainer import threat_explainer


class ThreatDetectionService:
    """
    Threat Detection Service integrating the Ensemble Threat Detector,
    Feature Engineering Pipeline, and SHAP Explainer.
    Provides single and batch inference with sub-millisecond latency.
    """

    def __init__(self):
        self.ensemble = EnsembleThreatDetector()
        self.is_ready = False
        self._initialize()

    def _initialize(self):
        models_dir = settings.SAVED_MODELS_DIR
        try:
            if (models_dir / "random_forest.joblib").exists():
                logger.info("loading_pre_trained_models", directory=str(models_dir))
                self.ensemble.load(models_dir)
                if self.ensemble.xgb.is_fitted:
                    threat_explainer.initialize_with_model(self.ensemble.xgb.model)
                self.is_ready = True
                logger.info("threat_detection_service_ready")
            else:
                logger.info("pre_trained_models_not_found_standby")
                self.is_ready = False
        except Exception as e:
            logger.warning("failed_to_load_models", error=str(e))
            self.is_ready = False

    def predict_event(self, event_dict: dict) -> dict:
        """
        Run feature extraction, ensemble threat detection, and SHAP explainability.
        """
        feat_vec = feature_pipeline.to_feature_vector(event_dict)

        if self.is_ready and self.ensemble.is_fitted:
            result = self.ensemble.predict_single(feat_vec)
            prediction = result["prediction"]
            confidence = result["confidence"]
            latency_ms = result["latency_ms"]
        else:
            # Fallback heuristic if models haven't been trained yet
            prediction, confidence, latency_ms = self._heuristic_prediction(event_dict)

        # Generate SHAP explanation
        explanation_data = threat_explainer.explain_instance(
            feature_vector=feat_vec,
            prediction=prediction,
            confidence=confidence,
        )

        return {
            "prediction": prediction,
            "confidence": confidence,
            "latency_ms": latency_ms,
            "feature_contributions": explanation_data["all_contributions"],
            "top_features": explanation_data["top_features"],
            "explanation": explanation_data["explanation"],
            "model_version": "ensemble_v1.0" if self.is_ready else "heuristic_v0.1",
        }

    async def detect_and_record(
        self,
        db: AsyncSession,
        event: NetworkEvent,
    ) -> ThreatPrediction:
        """
        Run threat detection on a NetworkEvent ORM instance and record the result in DB.
        """
        event_dict = {
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
            "event_time": event.event_time,
        }

        detection = self.predict_event(event_dict)

        prediction_record = ThreatPrediction(
            event_id=event.id,
            prediction=detection["prediction"],
            confidence=detection["confidence"],
            model_version=detection["model_version"],
            feature_contributions=detection["feature_contributions"],
            explanation=detection["explanation"],
        )
        db.add(prediction_record)
        await db.flush()

        logger.info(
            "threat_prediction_recorded",
            event_id=event.id,
            prediction=detection["prediction"],
            confidence=round(detection["confidence"], 3),
            latency_ms=round(detection["latency_ms"], 2),
        )
        return prediction_record

    def _heuristic_prediction(self, event_dict: dict) -> tuple[str, float, float]:
        start = time.perf_counter()
        failed_logins = int(event_dict.get("failed_login_count", 0))
        conn_rate = float(event_dict.get("connection_rate", 1.0))
        pkts = int(event_dict.get("packet_count", 1))

        # Simple threshold heuristics
        if failed_logins >= 5 or conn_rate > 30.0 or pkts > 500:
            pred = "MALICIOUS"
            conf = min(0.99, 0.70 + (failed_logins * 0.05) + (conn_rate * 0.005))
        else:
            pred = "BENIGN"
            conf = 0.92

        latency = (time.perf_counter() - start) * 1000.0
        return pred, float(conf), float(latency)


threat_detector_service = ThreatDetectionService()
