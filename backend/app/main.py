from fastapi import FastAPI

app = FastAPI(
    title="Argowei API",
    description="API for Argowei network intelligence and device management.",
    version="0.1.0",
)


@app.get("/api")
async def root() -> dict[str, str]:
    return {"name": "Argowei API", "version": app.version}


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
