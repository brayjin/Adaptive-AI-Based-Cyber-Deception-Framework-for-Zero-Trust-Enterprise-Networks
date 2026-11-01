from fastapi import APIRouter, Depends, HTTPException, status

from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.services.audit_trail import reconstruct_audit_chain


router = APIRouter(prefix="/audit", tags=["Audit"])


def _serialize(chain: dict) -> dict:
    event = chain.get("event")
    predictions = chain.get("predictions", [])
    evaluations = chain.get("evaluations", [])
    return {
        "event_id": chain.get("event_id"),
        "status": chain.get("status"),
        "missing_stages": chain.get("missing_stages", []),
        "event": (
            {
                "id": event.id,
                "event_time": event.event_time.isoformat() if event.event_time else None,
                "source_ip": event.source_ip,
                "dest_ip": event.dest_ip,
                "dest_port": event.dest_port,
                "protocol": event.protocol,
                "dataset_source": event.dataset_source,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }
            if event
            else None
        ),
        "predictions": [
            {
                "id": p.id,
                "event_id": p.event_id,
                "prediction": p.prediction,
                "confidence": p.confidence,
                "model_version": p.model_version,
                "feature_contributions": p.feature_contributions,
                "explanation": p.explanation,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in predictions
        ],
        "evaluations": [
            {
                "id": ev["evaluation"].id,
                "event_id": ev["evaluation"].event_id,
                "prediction_id": ev["evaluation"].prediction_id,
                "identity_score": ev["evaluation"].identity_score,
                "device_score": ev["evaluation"].device_score,
                "behaviour_score": ev["evaluation"].behaviour_score,
                "context_score": ev["evaluation"].context_score,
                "network_score": ev["evaluation"].network_score,
                "composite_risk_score": ev["evaluation"].composite_risk_score,
                "trust_decision": ev["evaluation"].trust_decision,
                "evaluation_details": ev["evaluation"].evaluation_details,
                "created_at": ev["evaluation"].created_at.isoformat() if ev["evaluation"].created_at else None,
                "deception_actions": [
                    {
                        "id": a["action"].id,
                        "evaluation_id": a["action"].evaluation_id,
                        "strategy_selected": a["action"].strategy_selected,
                        "strategy_reason": a["action"].strategy_reason,
                        "deception_target": a["action"].deception_target,
                        "rl_reward": a["action"].rl_reward,
                        "rl_state": a["action"].rl_state,
                        "rl_action": a["action"].rl_action,
                        "interaction_log": a["interactions"],
                        "attacker_engagement_time": a["action"].attacker_engagement_time,
                        "deception_success": a["action"].deception_success,
                        "started_at": a["action"].started_at.isoformat() if a["action"].started_at else None,
                        "ended_at": a["action"].ended_at.isoformat() if a["action"].ended_at else None,
                    }
                    for a in ev["deception_actions"]
                ],
            }
            for ev in evaluations
        ],
    }


@router.get("/events/{event_id}")
async def get_audit_chain(event_id: str, db: AsyncSession = Depends(get_db)):
    chain = await reconstruct_audit_chain(db, event_id)
    if chain.get("event") is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return _serialize(chain)