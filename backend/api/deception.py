from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.deception import DeceptionAction
from backend.models.evaluations import ZeroTrustEvaluation
from backend.schemas.deception import (
    AttackerInteractRequest,
    AttackerInteractResponse,
    DeceptionDecisionRequest,
    DeceptionActionResponse,
)
from backend.services.deception import STRATEGIES, deception_service
from backend.services.honeypots import honeypot_registry


router = APIRouter(prefix="/deception", tags=["Cyber Deception"])


@router.get("/strategies", response_model=list[str])
async def get_strategies():
    return list(STRATEGIES)


@router.get("/twin/status")
async def get_twin_status():
    return {**honeypot_registry.status(), "active_sessions": 0}


@router.post(
    "/decide",
    response_model=DeceptionActionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def decide_deception(
    request: DeceptionDecisionRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ZeroTrustEvaluation).where(
            ZeroTrustEvaluation.id == request.evaluation_id
        )
    )
    evaluation = result.scalar_one_or_none()
    if evaluation is None:
        raise HTTPException(status_code=404, detail="Evaluation not found")

    try:
        return await deception_service.decide(db, evaluation, request.strategy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/actions", response_model=list[DeceptionActionResponse])
async def get_actions(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    return await deception_service.list_actions(db, limit, offset)


@router.post("/interact", response_model=AttackerInteractResponse)
async def interact_with_deception(
    request: AttackerInteractRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DeceptionAction).where(DeceptionAction.id == request.action_id)
    )
    action = result.scalar_one_or_none()
    if action is None:
        raise HTTPException(status_code=404, detail="Deception action not found")
    try:
        return await deception_service.record_interaction(
            db,
            action,
            request.session_id,
            request.service_type,
            request.input_text,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc