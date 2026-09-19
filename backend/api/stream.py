import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from backend.database import AsyncSessionLocal
from backend.models.events import NetworkEvent


router = APIRouter(tags=["Realtime Stream"])


@router.websocket("/ws/events")
async def stream_events(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(NetworkEvent)
                    .order_by(NetworkEvent.event_time.desc())
                    .limit(20)
                )
                events = [
                    {
                        "id": event.id,
                        "event_time": event.event_time.isoformat(),
                        "source_ip": event.source_ip,
                        "dest_ip": event.dest_ip,
                        "dest_port": event.dest_port,
                        "protocol": event.protocol,
                    }
                    for event in result.scalars().all()
                ]
            await websocket.send_json({"type": "event_snapshot", "events": events})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return