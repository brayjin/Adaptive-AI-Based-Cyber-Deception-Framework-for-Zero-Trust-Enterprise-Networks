import asyncio
from backend.database import AsyncSessionLocal, init_db
from backend.services.data_ingestion import data_ingestion_service
from backend.utils.logging import logger, setup_logging


async def seed_events(count: int = 500):
    setup_logging()
    logger.info("seeding_database_events", count=count)
    await init_db()
    
    async with AsyncSessionLocal() as db:
        event_ids = await data_ingestion_service.generate_and_ingest_synthetic(
            db=db,
            count=count,
            scenario="mixed"
        )
        await db.commit()
        total = await data_ingestion_service.get_total_event_count(db)
        logger.info("database_seeded_successfully", ingested=len(event_ids), total_in_db=total)


if __name__ == "__main__":
    asyncio.run(seed_events(500))
