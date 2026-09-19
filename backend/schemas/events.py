from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class NetworkEventBase(BaseModel):
    source_ip: str = Field(..., json_schema_extra={"example": "192.168.1.105"})
    dest_ip: str = Field(..., json_schema_extra={"example": "10.0.0.5"})
    source_port: int = Field(..., ge=0, le=65535, json_schema_extra={"example": 54321})
    dest_port: int = Field(..., ge=0, le=65535, json_schema_extra={"example": 22})
    protocol: str = Field("TCP", json_schema_extra={"example": "TCP"})
    packet_count: int = Field(1, ge=1, json_schema_extra={"example": 15})
    bytes_sent: int = Field(0, ge=0, json_schema_extra={"example": 1200})
    bytes_received: int = Field(0, ge=0, json_schema_extra={"example": 4500})
    connection_rate: float = Field(1.0, ge=0.0, json_schema_extra={"example": 12.5})
    failed_login_count: int = Field(0, ge=0, json_schema_extra={"example": 5})
    session_duration: float = Field(0.0, ge=0.0, json_schema_extra={"example": 3.2})
    raw_features: dict = Field(default_factory=dict)
    dataset_source: str = Field("synthetic", json_schema_extra={"example": "CICIDS2017"})


class NetworkEventCreate(NetworkEventBase):
    pass


class NetworkEventResponse(NetworkEventBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_time: datetime
    created_at: datetime


class EventBatchIngestRequest(BaseModel):
    events: list[NetworkEventCreate]
    dataset_source: str = "batch_api"


class EventBatchIngestResponse(BaseModel):
    ingested_count: int
    event_ids: list[str]
    message: str


class SyntheticEventGenerateRequest(BaseModel):
    scenario: str = Field("mixed", description="Scenario: mixed, ddos, portscan, bruteforce, sqli, benign")
    count: int = Field(50, ge=1, le=10000, description="Number of events to generate")
