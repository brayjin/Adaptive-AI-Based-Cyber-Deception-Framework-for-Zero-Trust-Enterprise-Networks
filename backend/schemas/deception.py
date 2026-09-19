from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class DeceptionActionBase(BaseModel):
    strategy_selected: str = Field(..., json_schema_extra={"example": "FAKE_SSH"})
    strategy_reason: str = Field("", json_schema_extra={"example": "High-confidence SSH brute-force attempt detected"})
    deception_target: str = Field("honeypot_ssh", json_schema_extra={"example": "honeypot_ssh"})
    attacker_engagement_time: float = Field(0.0, ge=0.0)
    deception_success: bool = Field(False)
    rl_reward: float = Field(0.0)


class DeceptionActionResponse(DeceptionActionBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evaluation_id: str
    interaction_log: list[dict]
    rl_state: list[float]
    rl_action: str
    started_at: datetime
    ended_at: datetime | None = None


class AttackerInteractRequest(BaseModel):
    session_id: str
    service_type: str = Field(..., json_schema_extra={"example": "ssh"})  # ssh, web, db, credentials
    input_text: str = Field(..., json_schema_extra={"example": "cat /etc/passwd"})


class AttackerInteractResponse(BaseModel):
    session_id: str
    service_type: str
    response_text: str
    latency_ms: float
    is_sandboxed: bool = True
