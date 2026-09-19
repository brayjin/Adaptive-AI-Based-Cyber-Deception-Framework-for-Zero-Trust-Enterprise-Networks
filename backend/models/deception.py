import uuid
from datetime import datetime
from sqlalchemy import String, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.database import Base


class DeceptionAction(Base):
    __tablename__ = "deception_actions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evaluation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("zero_trust_evaluations.id", ondelete="CASCADE"), index=True
    )
    
    # Selected Strategy: FAKE_SSH, FAKE_WEB, FAKE_DB, FAKE_CREDENTIALS, DIGITAL_TWIN, NORMAL_RESPONSE
    strategy_selected: Mapped[str] = mapped_column(String(50), index=True)
    strategy_reason: Mapped[str] = mapped_column(String(255), default="")
    deception_target: Mapped[str] = mapped_column(String(100), default="honeypot")
    
    # Interaction monitoring
    interaction_log: Mapped[list[dict]] = mapped_column(JSON, default=list)
    attacker_engagement_time: Mapped[float] = mapped_column(Float, default=0.0)
    deception_success: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # RL agent details
    rl_reward: Mapped[float] = mapped_column(Float, default=0.0)
    rl_state: Mapped[list[float]] = mapped_column(JSON, default=list)
    rl_action: Mapped[int] = mapped_column(String(20), default="0")
    
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationship
    evaluation: Mapped["ZeroTrustEvaluation"] = relationship("ZeroTrustEvaluation", back_populates="deception_actions")
