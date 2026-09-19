from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from backend.config import settings
from backend.database import get_db
from backend.schemas.dashboard import SystemHealthResponse

router = APIRouter(prefix="/system", tags=["System"])


@router.get("/health", response_model=SystemHealthResponse)
async def get_health(db: AsyncSession = Depends(get_db)):
    db_status = "HEALTHY"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"UNHEALTHY: {str(e)}"

    return SystemHealthResponse(
        status="ONLINE" if db_status == "HEALTHY" else "DEGRADED",
        version=settings.VERSION,
        database=db_status,
        active_components={
            "api_server": "ONLINE",
            "data_ingestion": "ONLINE",
            "feature_engineering": "ONLINE",
            "synthetic_generator": "ONLINE",
            "threat_detector": "STANDBY",
            "zero_trust_engine": "STANDBY",
            "deception_controller": "STANDBY",
            "reinforcement_learning": "STANDBY",
            "federated_learning": "STANDBY",
        },
        timestamp=datetime.utcnow(),
    )
