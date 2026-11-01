import numpy as np
import pandas as pd
from datetime import datetime
from backend.config import settings
from backend.utils.logging import logger


class FeatureEngineeringPipeline:
    """
    Feature Engineering Pipeline for cyber-threat detection and Zero Trust risk scoring.
    Extracts, calculates derived signals, and normalizes tabular network event features.
    """

    PROTOCOL_MAP = {
        "TCP": 6,
        "UDP": 17,
        "ICMP": 1,
        "HTTP": 80,
        "HTTPS": 443,
        "SSH": 22,
        "DNS": 53,
    }

    def __init__(self):
        self.feature_names = settings.FEATURE_NAMES

    def extract_features_from_dict(self, event_dict: dict) -> dict[str, float]:
        """
        Extract derived and base numeric features from a single event dictionary.
        """
        dest_port = self._safe_int(event_dict.get("dest_port", 80), 80)
        protocol_str = str(event_dict.get("protocol", "TCP")).upper()
        protocol_num = self.PROTOCOL_MAP.get(protocol_str, 6)
        
        packet_count = self._safe_float(event_dict.get("packet_count", 1), 1.0)
        bytes_sent = self._safe_float(event_dict.get("bytes_sent", 0), 0.0)
        bytes_received = self._safe_float(event_dict.get("bytes_received", 0), 0.0)
        connection_rate = self._safe_float(event_dict.get("connection_rate", 1.0), 1.0)
        failed_login_count = self._safe_float(event_dict.get("failed_login_count", 0), 0.0)
        session_duration = max(0.001, self._safe_float(event_dict.get("session_duration", 0.1), 0.1))

        # Derived features
        bytes_ratio = bytes_sent / (bytes_received + 1.0)
        port_diversity = self._safe_float(event_dict.get("port_diversity", 1), 1.0)
        
        # Time of day (fraction 0.0 - 1.0)
        event_time = event_dict.get("event_time")
        if isinstance(event_time, str):
            try:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                time_of_day = (dt.hour * 3600 + dt.minute * 60 + dt.second) / 86400.0
            except Exception:
                time_of_day = 0.5
        elif isinstance(event_time, datetime):
            time_of_day = (event_time.hour * 3600 + event_time.minute * 60 + event_time.second) / 86400.0
        else:
            time_of_day = 0.5

        is_privileged_port = 1.0 if dest_port < 1024 else 0.0
        connection_frequency = self._safe_float(event_dict.get("connection_frequency", connection_rate * 60.0), connection_rate * 60.0)
        packets_per_second = packet_count / session_duration

        features = {
            "dest_port": float(dest_port),
            "protocol_num": float(protocol_num),
            "packet_count": packet_count,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "connection_rate": connection_rate,
            "failed_login_count": failed_login_count,
            "session_duration": session_duration,
            "bytes_ratio": float(bytes_ratio),
            "port_diversity": port_diversity,
            "time_of_day": float(time_of_day),
            "is_privileged_port": is_privileged_port,
            "connection_frequency": connection_frequency,
            "packets_per_second": float(packets_per_second),
        }
        return features

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        try:
            if value is None:
                return default
            return int(value)
        except (TypeError, ValueError):
            try:
                return int(float(value))
            except (TypeError, ValueError):
                return default

    @staticmethod
    def _safe_float(value, default: float = 0.0) -> float:
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def merge_computed_features(self, event_dict: dict) -> dict:
        merged = dict(event_dict or {})
        candidates = []
        raw = merged.get("raw_features")
        if isinstance(raw, dict):
            candidates.append(raw.get("computed_features"))
        candidates.append(merged.get("computed_features"))
        for computed in candidates:
            if isinstance(computed, dict):
                for key, value in computed.items():
                    if key in self.feature_names:
                        merged[key] = value
        return merged

    def extract_features_from_event(self, event) -> dict[str, float]:
        event_dict = {
            "source_ip": getattr(event, "source_ip", None),
            "dest_ip": getattr(event, "dest_ip", None),
            "source_port": getattr(event, "source_port", 0),
            "dest_port": getattr(event, "dest_port", 80),
            "protocol": getattr(event, "protocol", "TCP"),
            "packet_count": getattr(event, "packet_count", 1),
            "bytes_sent": getattr(event, "bytes_sent", 0),
            "bytes_received": getattr(event, "bytes_received", 0),
            "connection_rate": getattr(event, "connection_rate", 1.0),
            "failed_login_count": getattr(event, "failed_login_count", 0),
            "session_duration": getattr(event, "session_duration", 0.0),
            "event_time": getattr(event, "event_time", None),
            "raw_features": getattr(event, "raw_features", None) or {},
        }
        event_dict = self.merge_computed_features(event_dict)
        return self.extract_features_from_dict(event_dict)

    def to_feature_vector(self, event_dict: dict) -> np.ndarray:
        """
        Convert a single event to a 1D numpy array aligned with self.feature_names.
        """
        merged = self.merge_computed_features(event_dict)
        feat_dict = self.extract_features_from_dict(merged)
        return np.array([self._safe_float(feat_dict.get(col, 0.0), 0.0) for col in self.feature_names], dtype=np.float32)

    def transform_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform a pandas DataFrame of raw network events into the standard feature matrix.
        """
        records = df.to_dict(orient="records")
        extracted = [self.extract_features_from_dict(r) for r in records]
        feature_df = pd.DataFrame(extracted)[self.feature_names]
        return feature_df


feature_pipeline = FeatureEngineeringPipeline()
