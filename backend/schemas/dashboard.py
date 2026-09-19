from datetime import datetime
from pydantic import BaseModel, Field


class DashboardSummary(BaseModel):
    total_events: int = 0
    total_threats_detected: int = 0
    active_deceptions: int = 0
    avg_risk_score: float = 0.0
    zero_trust_distribution: dict[str, int] = Field(default_factory=dict)
    threat_types_distribution: dict[str, int] = Field(default_factory=dict)
    system_status: str = "HEALTHY"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SystemHealthResponse(BaseModel):
    status: str
    version: str
    database: str
    active_components: dict[str, str]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
