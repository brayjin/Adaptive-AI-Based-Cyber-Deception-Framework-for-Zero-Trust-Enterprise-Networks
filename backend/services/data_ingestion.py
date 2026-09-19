import os
import uuid
from datetime import datetime
from pathlib import Path
import pandas as pd
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from backend.models.events import NetworkEvent
from backend.services.feature_engineering import feature_pipeline
from backend.services.synthetic_data import synthetic_generator
from backend.utils.logging import logger


class DataIngestionService:
    """
    Orchestrates ingestion of cybersecurity datasets (CICIDS2017, UNSW-NB15)
    and synthetic network telemetry into the database.
    """

    @staticmethod
    async def ingest_event_dict_batch(
        db: AsyncSession,
        events_data: list[dict],
        dataset_source: str = "batch_api"
    ) -> list[str]:
        """
        Validate, extract features, and store a batch of event dictionaries.
        """
        event_models = []
        event_ids = []

        for item in events_data:
            eid = item.get("id") or str(uuid.uuid4())
            
            # Parse datetime safely
            event_time_val = item.get("event_time")
            if isinstance(event_time_val, str):
                try:
                    event_time = datetime.fromisoformat(event_time_val.replace("Z", "+00:00"))
                except Exception:
                    event_time = datetime.utcnow()
            elif isinstance(event_time_val, datetime):
                event_time = event_time_val
            else:
                event_time = datetime.utcnow()

            # Extract features for storage and consistency
            feat_dict = feature_pipeline.extract_features_from_dict(item)
            raw_features = item.get("raw_features", {})
            raw_features.update({"computed_features": feat_dict})

            event = NetworkEvent(
                id=eid,
                event_time=event_time,
                source_ip=str(item.get("source_ip", "10.0.0.1")),
                dest_ip=str(item.get("dest_ip", "10.0.0.2")),
                source_port=int(item.get("source_port", 0)),
                dest_port=int(item.get("dest_port", 80)),
                protocol=str(item.get("protocol", "TCP")),
                packet_count=int(item.get("packet_count", 1)),
                bytes_sent=int(item.get("bytes_sent", 0)),
                bytes_received=int(item.get("bytes_received", 0)),
                connection_rate=float(item.get("connection_rate", 1.0)),
                failed_login_count=int(item.get("failed_login_count", 0)),
                session_duration=float(item.get("session_duration", 0.0)),
                raw_features=raw_features,
                dataset_source=dataset_source,
            )
            event_models.append(event)
            event_ids.append(eid)

        db.add_all(event_models)
        await db.flush()
        logger.info("ingested_events_batch", count=len(event_models), source=dataset_source)
        return event_ids

    @staticmethod
    async def generate_and_ingest_synthetic(
        db: AsyncSession,
        count: int = 100,
        scenario: str = "mixed"
    ) -> list[str]:
        """
        Generate synthetic events and persist them into the database.
        """
        events = synthetic_generator.generate_batch(count=count, scenario=scenario)
        return await DataIngestionService.ingest_event_dict_batch(
            db=db,
            events_data=events,
            dataset_source=f"synthetic_{scenario}"
        )

    @staticmethod
    async def get_total_event_count(db: AsyncSession) -> int:
        result = await db.execute(select(func.count(NetworkEvent.id)))
        return result.scalar() or 0

    @staticmethod
    async def query_events(
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        source_ip: str | None = None,
        dest_port: int | None = None
    ) -> list[NetworkEvent]:
        query = select(NetworkEvent).order_by(NetworkEvent.event_time.desc())
        if source_ip:
            query = query.where(NetworkEvent.source_ip == source_ip)
        if dest_port is not None:
            query = query.where(NetworkEvent.dest_port == dest_port)
        query = query.limit(limit).offset(offset)
        result = await db.execute(query)
        return list(result.scalars().all())


data_ingestion_service = DataIngestionService()
