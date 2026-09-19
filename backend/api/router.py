from fastapi import APIRouter
from backend.api.health import router as health_router
from backend.api.events import router as events_router
from backend.api.detection import router as detection_router
from backend.api.zerotrust import router as zerotrust_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(events_router)
api_router.include_router(detection_router)
api_router.include_router(zerotrust_router)
