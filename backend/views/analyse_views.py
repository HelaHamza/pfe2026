# import asyncio
# import json
# from fastapi import APIRouter, Depends
# from fastapi.responses import StreamingResponse

# from controllers.analyse_controller import run_analyse, get_state
# from core.deps import get_current_user

# router = APIRouter(prefix="/run", tags=["Analyse"])


# @router.post("/analyse")
# async def start_analyse(current_user: dict = Depends(get_current_user)):
#     """Lance une analyse SOC (AE + Sigma + LLM)."""
#     state = get_state()
#     if state["running"]:
#         return {"status": "already_running", "started_at": state["started_at"]}
#     asyncio.create_task(run_analyse())
#     return {"status": "started"}


# @router.get("/analyse/status")
# def analyse_status(current_user: dict = Depends(get_current_user)):
#     state = get_state()
#     return {
#         "running":    state["running"],
#         "done":       state["done"],
#         "started_at": state["started_at"],
#         "error":      state["error"],
#         "last_log":   state["logs"][-1]["msg"] if state["logs"] else None,
#     }


# @router.get("/analyse/stream")
# async def stream_progress():
#     """
#     SSE pour suivre la progression en temps réel.
#     Note : EventSource ne supportant pas les headers, l'auth ici est faite
#     via le proxy Vite ou via un token en query string (à toi de voir).
#     """
#     async def generator():
#         sent = 0
#         while True:
#             state = get_state()
#             logs  = state["logs"]
#             while sent < len(logs):
#                 yield f"data: {json.dumps(logs[sent])}\n\n"
#                 sent += 1
#             if state["done"] and sent >= len(logs) and sent > 0:
#                 yield f"data: {json.dumps({'msg': '__DONE__'})}\n\n"
#                 break
#             yield ": keepalive\n\n"
#             await asyncio.sleep(0.5)

#     return StreamingResponse(
#         generator(),
#         media_type="text/event-stream",
#         headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
#     )