import uuid
from datetime import datetime
from sqlalchemy import String, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.database import Base


class ModelMetric(Base):
    __tablename__ = "model_metrics"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    model_name: Mapped[str] = mapped_column(String(100), index=True)
    model_version: Mapped[str] = mapped_column(String(50))
    
    accuracy: Mapped[float] = mapped_column(Float)
    precision_score: Mapped[float] = mapped_column(Float)
    recall: Mapped[float] = mapped_column(Float)
    f1_score: Mapped[float] = mapped_column(Float)
    roc_auc: Mapped[float] = mapped_column(Float)
    fpr: Mapped[float] = mapped_column(Float)
    fnr: Mapped[float] = mapped_column(Float)
    detection_latency_ms: Mapped[float] = mapped_column(Float)
    
    confusion_matrix: Mapped[list[list[int]]] = mapped_column(JSON, default=list)
    classification_report: Mapped[dict] = mapped_column(JSON, default=dict)
    dataset_used: Mapped[str] = mapped_column(String(50))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
