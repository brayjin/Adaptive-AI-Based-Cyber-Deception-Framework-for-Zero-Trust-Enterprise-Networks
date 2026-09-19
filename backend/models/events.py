import uuid
from datetime import datetime
from sqlalchemy import String, Integer, BigInteger, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.database import Base


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    event_time: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    dest_ip: Mapped[str] = mapped_column(String(45), index=True)
    source_port: Mapped[int] = mapped_column(Integer)
    dest_port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(10), default="TCP")
    
    packet_count: Mapped[int] = mapped_column(BigInteger, default=1)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_received: Mapped[int] = mapped_column(BigInteger, default=0)
    connection_rate: Mapped[float] = mapped_column(Float, default=1.0)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    session_duration: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Store arbitrary raw/derived features as JSON
    raw_features: Mapped[dict] = mapped_column(JSON, default=dict)
    dataset_source: Mapped[str] = mapped_column(String(50), default="synthetic")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    predictions: Mapped[list["ThreatPrediction"]] = relationship(
        "ThreatPrediction", back_populates="event", cascade="all, delete-orphan"
    )
    evaluations: Mapped[list["ZeroTrustEvaluation"]] = relationship(
        "ZeroTrustEvaluation", back_populates="event", cascade="all, delete-orphan"
    )
