from fastapi import FastAPI

from app.api.routes.assistant import router as assistant_router
from app.settings import APP_VERSION


app = FastAPI(
    title="AegisAl Standalone Security Assistant",
    version=APP_VERSION,
    description="Standalone LangGraph security Q&A service provided by AegisAl.",
)
app.include_router(assistant_router)


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aegisai-standalone-security-assistant",
        "version": APP_VERSION,
        "docs": "/docs",
        "assistant_api": "/api/assistant",
    }


@app.get("/health")
def health() -> dict[str, object]:
    return {"ok": True, "service": "aegisai-standalone-security-assistant", "version": APP_VERSION}
