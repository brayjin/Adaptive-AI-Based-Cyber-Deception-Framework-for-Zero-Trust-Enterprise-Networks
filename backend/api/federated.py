from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.federated import FederatedRound
from backend.services.federated_learning import federated_simulation


router = APIRouter(prefix="/federated", tags=["Federated Learning"])


@router.post("/start")
async def start_federated_training(
    rounds: int = Query(20, ge=1, le=20),
    samples_per_client: int = Query(20, ge=4, le=500),
    db: AsyncSession = Depends(get_db),
):
    result = federated_simulation.run(rounds, samples_per_client)
    for item in result["history"]:
        db.add(
            FederatedRound(
                round_number=item["round_number"],
                num_clients=item["num_clients"],
                aggregation_strategy=result["aggregation_strategy"],
                client_metrics=item["client_metrics"],
                global_metrics=item["global_metrics"],
            )
        )
    await db.flush()
    return {
        "rounds_completed": rounds,
        "domains": result["domains"],
        "aggregation_strategy": result["aggregation_strategy"],
        "history": result["history"],
    }


@router.get("/rounds")
async def get_federated_rounds(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        FederatedRound.__table__.select()
        .order_by(FederatedRound.round_number.desc())
        .limit(limit)
    )
    return [dict(row) for row in result.mappings().all()]