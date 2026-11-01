import uuid
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
        return {
            "event_id": event_id,
            "status": "not_found",
            "missing_stages": ["event"],
            "event": None,
            "predictions": [],
            "evaluations": [],
        }

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

    missing = []
    if not predictions:
        missing.append("prediction")
    if not evaluations:
        missing.append("evaluation")
    if evaluations and not any(
        ev["deception_actions"] for ev in reconstructed_evaluations
    ):
        # only flag deception as missing for DECEIVE/BLOCK evaluations
        if any(ev["evaluation"].trust_decision in {"DECEIVE", "BLOCK"} for ev in reconstructed_evaluations):
            missing.append("deception_action")
    if any(
        ev["deception_actions"] and not any(
            a["interactions"] for a in ev["deception_actions"]
        )
        for ev in reconstructed_evaluations
    ):
        missing.append("interaction")

    status = "complete" if not missing else "incomplete"
    return {
        "event_id": event_id,
        "status": status,
        "missing_stages": missing,
        "event": event,
        "predictions": predictions,
        "evaluations": reconstructed_evaluations,
    }
