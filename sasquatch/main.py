"""
main.py — FastAPI application entrypoint with APScheduler lifecycle.
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv()

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from client_anomaly.api.routes import router
from client_anomaly.scheduler import create_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger(__name__)

app = FastAPI(title="Sasquatch — Client Anomaly Detection", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

_scheduler = create_scheduler()


@app.on_event("startup")
async def startup():
    _scheduler.start()
    log.info("APScheduler started")


@app.on_event("shutdown")
async def shutdown():
    _scheduler.shutdown(wait=False)
    log.info("APScheduler stopped")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
