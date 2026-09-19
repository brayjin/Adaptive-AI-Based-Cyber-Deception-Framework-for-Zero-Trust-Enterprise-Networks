import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.config import settings
from backend.database import get_db
from backend.models.events import NetworkEvent
from backend.models.predictions import ThreatPrediction
from backend.schemas.predictions import (
    DetectionRequest,
    ThreatPredictionResponse,
    ExplanationResponse,
)
from backend.services.threat_detector import threat_detector_service
from ml.explainability.shap_explainer import threat_explainer

router = APIRouter(prefix="/detection", tags=["Threat Detection"])


@router.post(
    "/detect",
    response_model=ThreatPredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a network event and generate threat prediction with SHAP explanation",
)
async def detect_threat(
    request: DetectionRequest,
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
        prediction = await threat_detector_service.detect_and_record(db, event)
        return prediction

    elif request.event_data:
        # Ad-hoc event dictionary without pre-existing event record
        detection = threat_detector_service.predict_event(request.event_data)
        
        # Save temporary event and prediction
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
            dataset_source="ad_hoc_api",
        )
        db.add(event)
        await db.flush()

        prediction = ThreatPrediction(
            event_id=event.id,
            prediction=detection["prediction"],
            confidence=detection["confidence"],
            model_version=detection["model_version"],
            feature_contributions=detection["feature_contributions"],
            explanation=detection["explanation"],
        )
        db.add(prediction)
        await db.flush()
        return prediction

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either 'event_id' or 'event_data'",
        )


@router.get(
    "/predictions",
    response_model=list[ThreatPredictionResponse],
    summary="Query threat predictions",
)
async def get_predictions(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    prediction: str | None = Query(None, description="Filter by BENIGN or MALICIOUS"),
    db: AsyncSession = Depends(get_db),
):
    query = select(ThreatPrediction).order_by(ThreatPrediction.created_at.desc())
    if prediction:
        query = query.where(ThreatPrediction.prediction == prediction.upper())
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get(
    "/predictions/{prediction_id}/explain",
    response_model=ExplanationResponse,
    summary="Retrieve SHAP feature contribution explanation for a threat prediction",
)
async def explain_prediction(
    prediction_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ThreatPrediction).where(ThreatPrediction.id == prediction_id))
    pred = result.scalar_one_or_none()
    if not pred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prediction with id '{prediction_id}' not found",
        )

    # Format top features from stored contributions
    contributions = pred.feature_contributions or {}
    top_features = []
    for feat, contrib in sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)[:5]:
        top_features.append({
            "feature": feat,
            "display_name": threat_explainer.FEATURE_DESCRIPTIONS.get(feat, feat),
            "contribution": contrib,
            "direction": "positive" if contrib > 0 else "negative",
        })

    return ExplanationResponse(
        prediction_id=pred.id,
        prediction=pred.prediction,
        confidence=pred.confidence,
        top_features=top_features,
        explanation=pred.explanation,
        model_version=pred.model_version,
    )


@router.get(
    "/models/metrics",
    summary="Get evaluation metrics of trained threat detection models",
)
async def get_model_metrics():
    metrics_file = settings.SAVED_MODELS_DIR / "evaluation_metrics.json"
    if metrics_file.exists():
        with open(metrics_file, "r") as f:
            return json.load(f)
    return {
        "status": "NOT_TRAINED",
        "message": "Models have not been trained yet. Run ml/train.py or trigger training.",
    }
