"""
avadhi/server/app.py — FastAPI webhook server for Agent Arena integration.

Usage:
    python -m avadhi serve --port 8000
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException

from avadhi.server.handler import process_task
from avadhi.server.schemas import WebhookPayload

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("avadhi.server")

KEEP_ALIVE_INTERVAL = 60  # seconds


async def _keep_alive_loop() -> None:
    """Ping own /health every minute to prevent Render free-tier spin-down."""
    port = int(os.getenv("PORT", "8000"))
    url = f"http://localhost:{port}/health"
    await asyncio.sleep(30)  # wait for server to fully start
    while True:
        try:
            async with httpx.AsyncClient() as client:
                await client.get(url, timeout=10)
            logger.debug("Keep-alive ping sent")
        except Exception as exc:
            logger.debug("Keep-alive ping failed: %s", exc)
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_keep_alive_loop())
    yield
    task.cancel()


app = FastAPI(
    title="Avadhi Agent Arena",
    description="Webhook server for Agent Arena smart contract audit tasks",
    lifespan=lifespan,
)

# Track active tasks
_active_tasks: dict[str, threading.Thread] = {}


def _get_webhook_token() -> str:
    token = os.getenv("WEBHOOK_AUTH_TOKEN", "")
    if not token:
        raise RuntimeError("WEBHOOK_AUTH_TOKEN not set")
    return token


@app.get("/")
def index():
    return {
        "status": "running",
        "service": "Avadhi Agent Arena Webhook Server",
        "health_check": "/health",
        "webhook_endpoint": "/webhook/audit",
    }


@app.get("/health")
def health():
    active = {tid: t.is_alive() for tid, t in _active_tasks.items()}
    return {"status": "ok", "active_tasks": active}


def _handle_webhook(payload: WebhookPayload, authorization: str) -> dict:
    """
    Core webhook handler logic, shared by POST / and POST /webhook/audit.
    Validates auth, handles test pings, and dispatches real tasks.
    """
    expected = f"token {_get_webhook_token()}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Invalid authorization token")

    task_id = payload.task_id
    logger.info("Received webhook for task %s", task_id)

    # Handle ping / test requests (no repo URL = test ping)
    if not task_id or task_id.upper() in ("TEST", "TESTTASK", "PING", "DUMMY") or not payload.task_repository_url:
        logger.info("Received test/ping webhook from Agent Arena")
        return {"status": "accepted", "message": "Test webhook connection successful", "task_id": task_id}

    # Check if task is already being processed
    existing = _active_tasks.get(task_id)
    if existing and existing.is_alive():
        logger.warning("Task %s is already being processed", task_id)
        return {"status": "already_processing", "task_id": task_id}

    # Dispatch to background thread
    thread = threading.Thread(
        target=process_task,
        args=(payload,),
        name=f"audit-{task_id}",
        daemon=True,
    )
    _active_tasks[task_id] = thread
    thread.start()

    logger.info("Task %s dispatched to background thread", task_id)
    return {"status": "accepted", "task_id": task_id}


@app.post("/")
def webhook_root(
    payload: WebhookPayload,
    authorization: str = Header(...),
):
    """
    Alias for POST /webhook/audit.
    Accepts Agent Arena tasks posted to the root URL (misconfigured webhook URL).
    """
    logger.info("POST / received — routing to webhook handler")
    return _handle_webhook(payload, authorization)


@app.post("/webhook/audit")
def webhook_audit(
    payload: WebhookPayload,
    authorization: str = Header(...),
):
    """Receive audit task from Agent Arena."""
    return _handle_webhook(payload, authorization)
