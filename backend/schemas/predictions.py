from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class ThreatPredictionBase(BaseModel):
    prediction: str = Field(..., json_schema_extra={"example": "MALICIOUS"})
    confidence: float = Field(..., ge=0.0, le=1.0, json_schema_extra={"example": 0.94})
    model_version: str = Field("ensemble_v1", json_schema_extra={"example": "ensemble_v1"})
    feature_contributions: dict = Field(default_factory=dict)
    explanation: str = Field("", json_schema_extra={"example": "High risk: Excessive failed login attempts and scanning rate."})


class ThreatPredictionCreate(ThreatPredictionBase):
    event_id: str


class ThreatPredictionResponse(ThreatPredictionBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    created_at: datetime


class DetectionRequest(BaseModel):
    event_id: str | None = None
    event_data: dict | None = None


class ExplanationResponse(BaseModel):
    prediction_id: str
    prediction: str
    confidence: float
    top_features: list[dict]
    explanation: str
    model_version: str
