from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core import config
from app.database import initialize_database

app = FastAPI(
    title="DefenceAI",
    description="Adaptive Cyber Deception and AI-Powered Honeypot Platform",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Ingest-Key"],
)

initialize_database()
app.include_router(router)


@app.get("/")
def home():
    return {"project": "DefenceAI", "status": "running",
            "docs": "/docs"}
