from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.database import init_db
from backend.api.router import api_router
from backend.api.stream import router as stream_router
from backend.utils.logging import setup_logging, logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_logging()
    logger.info(
        "starting_server",
        app_name=settings.PROJECT_NAME,
        version=settings.VERSION,
        db_url=settings.DATABASE_URL.split("@")[-1],  # redact credentials if present
    )
    # Automatically initialize tables if not already present
    await init_db()
    logger.info("database_initialized")
    yield
    # Shutdown
    logger.info("stopping_server")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Adaptive AI-Based Cyber Deception Framework for Zero Trust Enterprise Networks",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API endpoints
app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(stream_router)


@app.get("/", tags=["Root"])
async def root():
    return {
        "framework": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "api_v1": settings.API_V1_STR,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
