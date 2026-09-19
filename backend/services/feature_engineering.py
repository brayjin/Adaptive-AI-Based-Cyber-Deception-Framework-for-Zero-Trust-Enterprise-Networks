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
        dest_port = int(event_dict.get("dest_port", 80))
        protocol_str = str(event_dict.get("protocol", "TCP")).upper()
        protocol_num = self.PROTOCOL_MAP.get(protocol_str, 6)
        
        packet_count = float(event_dict.get("packet_count", 1))
        bytes_sent = float(event_dict.get("bytes_sent", 0))
        bytes_received = float(event_dict.get("bytes_received", 0))
        connection_rate = float(event_dict.get("connection_rate", 1.0))
        failed_login_count = float(event_dict.get("failed_login_count", 0))
        session_duration = max(0.001, float(event_dict.get("session_duration", 0.1)))

        # Derived features
        bytes_ratio = bytes_sent / (bytes_received + 1.0)
        port_diversity = float(event_dict.get("port_diversity", 1))
        
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
        connection_frequency = float(event_dict.get("connection_frequency", connection_rate * 60.0))
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

    def to_feature_vector(self, event_dict: dict) -> np.ndarray:
        """
        Convert a single event to a 1D numpy array aligned with self.feature_names.
        """
        feat_dict = self.extract_features_from_dict(event_dict)
        return np.array([feat_dict.get(col, 0.0) for col in self.feature_names], dtype=np.float32)

    def transform_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform a pandas DataFrame of raw network events into the standard feature matrix.
        """
        records = df.to_dict(orient="records")
        extracted = [self.extract_features_from_dict(r) for r in records]
        feature_df = pd.DataFrame(extracted)[self.feature_names]
        return feature_df


feature_pipeline = FeatureEngineeringPipeline()
