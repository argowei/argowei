from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import redis_client
from app.db.session import engine, get_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    yield
    # Release pooled connections on shutdown instead of leaking sockets
    # (relevant with --reload, which tears down and recreates the app).
    await engine.dispose()
    await redis_client.aclose()


app = FastAPI(
    title="Argowei API",
    description="API for Argowei network intelligence and device management.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/api")
async def root() -> dict[str, str]:
    return {"name": "Argowei API", "version": app.version}


@app.get("/api/health")
async def health(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    """Reports API liveness plus DB/Redis connectivity for compose healthchecks."""
    try:
        await db.execute(text("SELECT 1"))
        database_status = "ok"
    except Exception:
        database_status = "unavailable"

    try:
        await redis_client.ping()
        redis_status = "ok"
    except Exception:
        redis_status = "unavailable"

    return {"status": "ok", "database": database_status, "redis": redis_status}
