import uuid
from datetime import datetime
from sqlalchemy import String, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.database import Base


class ZeroTrustEvaluation(Base):
    __tablename__ = "zero_trust_evaluations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    event_id: Mapped[str] = mapped_column(String(36), ForeignKey("network_events.id", ondelete="CASCADE"), index=True)
    prediction_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("threat_predictions.id", ondelete="SET NULL"), nullable=True)

    # 5 Key Zero Trust Factors (0.0 to 1.0 risk contribution)
    identity_score: Mapped[float] = mapped_column(Float, default=0.0)
    device_score: Mapped[float] = mapped_column(Float, default=0.0)
    behaviour_score: Mapped[float] = mapped_column(Float, default=0.0)
    context_score: Mapped[float] = mapped_column(Float, default=0.0)
    network_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Aggregate Risk Score (0.0 to 1.0)
    composite_risk_score: Mapped[float] = mapped_column(Float, index=True)
    
    # Decisions: ALLOW, VERIFY, RESTRICT, DECEIVE, BLOCK
    trust_decision: Mapped[str] = mapped_column(String(20), index=True)
    evaluation_details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    event: Mapped["NetworkEvent"] = relationship("NetworkEvent", back_populates="evaluations")
    prediction: Mapped["ThreatPrediction | None"] = relationship("ThreatPrediction", back_populates="evaluations")
    deception_actions: Mapped[list["DeceptionAction"]] = relationship(
        "DeceptionAction", back_populates="evaluation", cascade="all, delete-orphan"
    )
