from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.database import get_db
from backend.models.events import NetworkEvent
from backend.models.predictions import ThreatPrediction
from backend.models.evaluations import ZeroTrustEvaluation
from backend.schemas.evaluations import (
    ZeroTrustEvaluationResponse,
    ZeroTrustPolicyConfig,
)
from backend.services.zero_trust import zero_trust_engine
from backend.services.risk_scorer import ZeroTrustPolicy

router = APIRouter(prefix="/zerotrust", tags=["Zero Trust"])


class ZeroTrustEvaluateRequest(BaseModel):
    event_id: str | None = None
    prediction_id: str | None = None
    event_data: dict | None = None


@router.post(
    "/evaluate",
    response_model=ZeroTrustEvaluationResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate Zero Trust risk and determine trust decision (ALLOW, VERIFY, RESTRICT, DECEIVE, BLOCK)",
)
async def evaluate_trust(
    request: ZeroTrustEvaluateRequest,
    db: AsyncSession = Depends(get_db),
):
    if request.event_id:
        result = await db.execute(select(NetworkEvent).where(NetworkEvent.id == request.event_id))
        event = result.scalar_one_or_none()
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"NetworkEvent with id '{request.event_id}' not found",
            )
        
        prediction = None
        if request.prediction_id:
            pred_result = await db.execute(
                select(ThreatPrediction).where(ThreatPrediction.id == request.prediction_id)
            )
            prediction = pred_result.scalar_one_or_none()

        evaluation = await zero_trust_engine.evaluate_event(
            db=db,
            event=event,
            prediction=prediction,
        )
        return evaluation

    elif request.event_data:
        # Create ad-hoc event
        event = NetworkEvent(
            source_ip=str(request.event_data.get("source_ip", "10.0.0.1")),
            dest_ip=str(request.event_data.get("dest_ip", "10.0.0.2")),
            source_port=int(request.event_data.get("source_port", 0)),
            dest_port=int(request.event_data.get("dest_port", 80)),
            protocol=str(request.event_data.get("protocol", "TCP")),
            packet_count=int(request.event_data.get("packet_count", 1)),
            bytes_sent=int(request.event_data.get("bytes_sent", 0)),
            bytes_received=int(request.event_data.get("bytes_received", 0)),
            connection_rate=float(request.event_data.get("connection_rate", 1.0)),
            failed_login_count=int(request.event_data.get("failed_login_count", 0)),
            session_duration=float(request.event_data.get("session_duration", 0.0)),
            dataset_source="ad_hoc_zt",
        )
        db.add(event)
        await db.flush()

        evaluation = await zero_trust_engine.evaluate_event(
            db=db,
            event=event,
            prediction=None,
        )
        return evaluation

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must specify either 'event_id' or 'event_data'",
        )


@router.get(
    "/evaluations",
    response_model=list[ZeroTrustEvaluationResponse],
    summary="Query Zero Trust evaluations",
)
async def get_evaluations(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: str | None = Query(None, description="Filter: ALLOW, VERIFY, RESTRICT, DECEIVE, BLOCK"),
    min_risk: float | None = Query(None, ge=0.0, le=1.0),
    db: AsyncSession = Depends(get_db),
):
    query = select(ZeroTrustEvaluation).order_by(ZeroTrustEvaluation.created_at.desc())
    if decision:
        query = query.where(ZeroTrustEvaluation.trust_decision == decision.upper())
    if min_risk is not None:
        query = query.where(ZeroTrustEvaluation.composite_risk_score >= min_risk)
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get(
    "/evaluations/{evaluation_id}",
    response_model=ZeroTrustEvaluationResponse,
    summary="Get single Zero Trust evaluation details",
)
async def get_evaluation_by_id(
    evaluation_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ZeroTrustEvaluation).where(ZeroTrustEvaluation.id == evaluation_id)
    )
    eval_record = result.scalar_one_or_none()
    if not eval_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ZeroTrustEvaluation with id '{evaluation_id}' not found",
        )
    return eval_record


@router.get(
    "/policy",
    response_model=ZeroTrustPolicyConfig,
    summary="Get current Zero Trust policy weights and thresholds",
)
async def get_policy():
    policy = zero_trust_engine.get_policy()
    return ZeroTrustPolicyConfig(
        weight_identity=policy.weight_identity,
        weight_device=policy.weight_device,
        weight_behaviour=policy.weight_behaviour,
        weight_context=policy.weight_context,
        weight_network=policy.weight_network,
        threshold_allow=policy.threshold_allow,
        threshold_verify=policy.threshold_verify,
        threshold_restrict=policy.threshold_restrict,
        threshold_deceive=policy.threshold_deceive,
    )


@router.put(
    "/policy",
    response_model=ZeroTrustPolicyConfig,
    summary="Update Zero Trust policy weights and decision thresholds at runtime",
)
async def update_policy(config: ZeroTrustPolicyConfig):
    new_policy = ZeroTrustPolicy(
        weight_identity=config.weight_identity,
        weight_device=config.weight_device,
        weight_behaviour=config.weight_behaviour,
        weight_context=config.weight_context,
        weight_network=config.weight_network,
        threshold_allow=config.threshold_allow,
        threshold_verify=config.threshold_verify,
        threshold_restrict=config.threshold_restrict,
        threshold_deceive=config.threshold_deceive,
    )
    updated = zero_trust_engine.update_policy(new_policy)
    return ZeroTrustPolicyConfig(
        weight_identity=updated.weight_identity,
        weight_device=updated.weight_device,
        weight_behaviour=updated.weight_behaviour,
        weight_context=updated.weight_context,
        weight_network=updated.weight_network,
        threshold_allow=updated.threshold_allow,
        threshold_verify=updated.threshold_verify,
        threshold_restrict=updated.threshold_restrict,
        threshold_deceive=updated.threshold_deceive,
    )
