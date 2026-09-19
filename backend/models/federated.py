import uuid
from datetime import datetime
from sqlalchemy import String, Integer, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.database import Base


class FederatedRound(Base):
    __tablename__ = "federated_rounds"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    round_number: Mapped[int] = mapped_column(Integer, index=True)
    num_clients: Mapped[int] = mapped_column(Integer, default=3)
    aggregation_strategy: Mapped[str] = mapped_column(String(50), default="FedAvg")
    
    client_metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    global_metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    improvement_delta: Mapped[float] = mapped_column(Float, default=0.0)
    completed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
