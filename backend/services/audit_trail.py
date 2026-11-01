from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.deception import DeceptionAction
from backend.models.evaluations import ZeroTrustEvaluation
from backend.models.events import NetworkEvent
from backend.models.predictions import ThreatPrediction


async def reconstruct_audit_chain(db: AsyncSession, event_id: str) -> dict:
    """Reconstruct the full Event -> Prediction -> Evaluation -> Deception -> Interaction chain."""
    event = await db.get(NetworkEvent, event_id)
    if event is None:
        return {"event": None, "predictions": [], "evaluations": []}

    pred_result = await db.execute(
        select(ThreatPrediction)
        .where(ThreatPrediction.event_id == event_id)
        .order_by(ThreatPrediction.created_at.asc())
    )
    predictions = list(pred_result.scalars().all())

    eval_result = await db.execute(
        select(ZeroTrustEvaluation)
        .where(ZeroTrustEvaluation.event_id == event_id)
        .order_by(ZeroTrustEvaluation.created_at.asc())
    )
    evaluations = list(eval_result.scalars().all())

    reconstructed_evaluations = []
    for evaluation in evaluations:
        action_result = await db.execute(
            select(DeceptionAction)
            .where(DeceptionAction.evaluation_id == evaluation.id)
            .order_by(DeceptionAction.started_at.asc())
        )
        actions = list(action_result.scalars().all())
        reconstructed_evaluations.append(
            {
                "evaluation": evaluation,
                "prediction": evaluation.prediction,
                "deception_actions": [
                    {
                        "action": action,
                        "interactions": list(action.interaction_log or []),
                    }
                    for action in actions
                ],
            }
        )

    return {
        "event": event,
        "predictions": predictions,
        "evaluations": reconstructed_evaluations,
    }
