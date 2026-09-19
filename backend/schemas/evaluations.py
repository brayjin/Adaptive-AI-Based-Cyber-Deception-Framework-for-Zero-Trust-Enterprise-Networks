from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class ZeroTrustEvaluationBase(BaseModel):
    identity_score: float = Field(..., ge=0.0, le=1.0)
    device_score: float = Field(..., ge=0.0, le=1.0)
    behaviour_score: float = Field(..., ge=0.0, le=1.0)
    context_score: float = Field(..., ge=0.0, le=1.0)
    network_score: float = Field(..., ge=0.0, le=1.0)
    composite_risk_score: float = Field(..., ge=0.0, le=1.0)
    trust_decision: str = Field(..., json_schema_extra={"example": "DECEIVE"})  # ALLOW, VERIFY, RESTRICT, DECEIVE, BLOCK
    evaluation_details: dict = Field(default_factory=dict)


class ZeroTrustEvaluationResponse(ZeroTrustEvaluationBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    prediction_id: str | None = None
    created_at: datetime


class ZeroTrustPolicyConfig(BaseModel):
    weight_identity: float = Field(0.20, ge=0.0, le=1.0)
    weight_device: float = Field(0.15, ge=0.0, le=1.0)
    weight_behaviour: float = Field(0.35, ge=0.0, le=1.0)
    weight_context: float = Field(0.15, ge=0.0, le=1.0)
    weight_network: float = Field(0.15, ge=0.0, le=1.0)
    threshold_allow: float = Field(0.20, ge=0.0, le=1.0)
    threshold_verify: float = Field(0.40, ge=0.0, le=1.0)
    threshold_restrict: float = Field(0.60, ge=0.0, le=1.0)
    threshold_deceive: float = Field(0.80, ge=0.0, le=1.0)
