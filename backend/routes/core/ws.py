from fastapi import APIRouter
from server import JWT_ALG, JWT_SECRET, WebSocket, WebSocketDisconnect, bus, jwt, logger  # noqa: F401

router = APIRouter()

# Auto-generated from routes.py section
# Section starts at line 2389

# ---------- WebSocket ----------
@router.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload["sub"]
    except jwt.PyJWTError:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    q = await bus.subscribe(user_id)
    try:
        await websocket.send_json({"type": "connected", "user_id": user_id})
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"ws error: {e}")
    finally:
        bus.unsubscribe(user_id, q)


