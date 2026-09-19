import uuid
from datetime import datetime
from sqlalchemy import String, Float, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.database import Base


class ThreatPrediction(Base):
    __tablename__ = "threat_predictions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    event_id: Mapped[str] = mapped_column(String(36), ForeignKey("network_events.id", ondelete="CASCADE"), index=True)
    prediction: Mapped[str] = mapped_column(String(50))  # BENIGN, MALICIOUS, DDOS, PORTSCAN, BRUTEFORCE, etc.
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    model_version: Mapped[str] = mapped_column(String(50), default="ensemble_v1")
    
    # SHAP feature contributions
    feature_contributions: Mapped[dict] = mapped_column(JSON, default=dict)
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    event: Mapped["NetworkEvent"] = relationship("NetworkEvent", back_populates="predictions")
    evaluations: Mapped[list["ZeroTrustEvaluation"]] = relationship(
        "ZeroTrustEvaluation", back_populates="prediction", cascade="all, delete-orphan"
    )
