from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.database import get_db
from backend.schemas.events import (
    NetworkEventCreate,
    NetworkEventResponse,
    EventBatchIngestRequest,
    EventBatchIngestResponse,
    SyntheticEventGenerateRequest,
)
from backend.services.data_ingestion import data_ingestion_service

router = APIRouter(prefix="/events", tags=["Events"])


@router.post(
    "/ingest",
    response_model=EventBatchIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a batch of network events",
)
async def ingest_events(
    request: EventBatchIngestRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        events_dicts = [e.model_dump() for e in request.events]
        event_ids = await data_ingestion_service.ingest_event_dict_batch(
            db=db,
            events_data=events_dicts,
            dataset_source=request.dataset_source,
        )
        return EventBatchIngestResponse(
            ingested_count=len(event_ids),
            event_ids=event_ids,
            message=f"Successfully ingested {len(event_ids)} network events",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest events: {str(e)}",
        )


@router.post(
    "/generate",
    response_model=EventBatchIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and ingest synthetic network events",
)
async def generate_synthetic_events(
    request: SyntheticEventGenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        event_ids = await data_ingestion_service.generate_and_ingest_synthetic(
            db=db,
            count=request.count,
            scenario=request.scenario,
        )
        return EventBatchIngestResponse(
            ingested_count=len(event_ids),
            event_ids=event_ids,
            message=f"Successfully generated and ingested {len(event_ids)} synthetic events ({request.scenario})",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate synthetic events: {str(e)}",
        )


@router.get(
    "",
    response_model=list[NetworkEventResponse],
    summary="Query ingested network events",
)
async def get_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source_ip: str | None = Query(None),
    dest_port: int | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    events = await data_ingestion_service.query_events(
        db=db,
        limit=limit,
        offset=offset,
        source_ip=source_ip,
        dest_port=dest_port,
    )
    return events


@router.get(
    "/count",
    response_model=dict[str, int],
    summary="Get total count of ingested events",
)
async def get_event_count(db: AsyncSession = Depends(get_db)):
    total = await data_ingestion_service.get_total_event_count(db)
    return {"total_events": total}
