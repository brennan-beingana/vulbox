import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.orchestrator import get_event_history, get_status_queue

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/runs/{run_id}/status")
async def run_status_ws(run_id: int, websocket: WebSocket):
    """Stream real-time pipeline status events for a run.

    Late subscribers receive prior events from the replay buffer first, then
    live events from the queue.
    """
    await websocket.accept()
    queue = get_status_queue(run_id)
    for past in get_event_history(run_id):
        await websocket.send_text(json.dumps(past))
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_text(json.dumps(event))
                if event.get("event") in ("complete", "failed", "error"):
                    break
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        pass
