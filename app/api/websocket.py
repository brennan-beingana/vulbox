import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.orchestrator import get_status_queue

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/runs/{run_id}/status")
async def run_status_ws(run_id: int, websocket: WebSocket):
    """Stream real-time pipeline status events for a run."""
    await websocket.accept()
    queue = get_status_queue(run_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_text(json.dumps(event))
                if event.get("event") in ("complete", "failed"):
                    break
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        pass
