from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Adaptive AI Cyber Deception Framework"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    
    # Database
    # Defaults to SQLite with aiosqlite for zero-friction local execution,
    # or override with postgresql+asyncpg://user:pass@localhost:5432/dbname in .env
    DATABASE_URL: str = "sqlite+aiosqlite:///./cyber_deception.db"
    DB_ECHO: bool = False
    
    # Security / Secret
    SECRET_KEY: str = "dev-insecure-secret-key-change-in-production-zt-framework"
    
    # Data Storage Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    DATASET_CICIDS2017_PATH: Path = DATA_DIR / "cicids2017"
    DATASET_UNSW_PATH: Path = DATA_DIR / "unsw_nb15"
    SAVED_MODELS_DIR: Path = BASE_DIR / "ml" / "saved_models"
    SAVED_POLICIES_DIR: Path = BASE_DIR / "rl" / "saved_policies"
    
    # Feature Engineering Config
    FEATURE_NAMES: list[str] = [
        "dest_port",
        "protocol_num",
        "packet_count",
        "bytes_sent",
        "bytes_received",
        "connection_rate",
        "failed_login_count",
        "session_duration",
        "bytes_ratio",
        "port_diversity",
        "time_of_day",
        "is_privileged_port",
        "connection_frequency",
        "packets_per_second",
    ]
    
    # Zero Trust Policy Defaults
    ZT_WEIGHT_IDENTITY: float = 0.20
    ZT_WEIGHT_DEVICE: float = 0.15
    ZT_WEIGHT_BEHAVIOUR: float = 0.35
    ZT_WEIGHT_CONTEXT: float = 0.15
    ZT_WEIGHT_NETWORK: float = 0.15
    
    ZT_THRESHOLD_ALLOW: float = 0.20
    ZT_THRESHOLD_VERIFY: float = 0.40
    ZT_THRESHOLD_RESTRICT: float = 0.60
    ZT_THRESHOLD_DECEIVE: float = 0.80
    
    # LLM & Deception
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2:3b"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
