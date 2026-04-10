"""
main.py — FastAPI application entrypoint with APScheduler lifecycle.
"""

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from client_anomaly.api.auth import auth_router
from client_anomaly.api.routes import router
from client_anomaly.scheduler import clear_stale_global_lock, create_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger(__name__)

_scheduler = create_scheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # A fresh process can't possibly be mid-flight on a background job, so any
    # lock left in Redis is stale from a previous run that crashed or was
    # killed before it could release. Clear it before the scheduler starts.
    await clear_stale_global_lock()
    _scheduler.start()
    log.info("APScheduler started")
    yield
    _scheduler.shutdown(wait=False)
    log.info("APScheduler stopped")


app = FastAPI(
    title="Sasquatch — Client Anomaly Detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(router)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
