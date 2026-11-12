import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

DB_PATH = Path(os.getenv("DEFENCEAI_DB", BASE_DIR / "defenceai.db"))

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

CORS_ORIGINS = os.getenv(
    "DEFENCEAI_CORS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

# If set, honeypots must send it as the X-Ingest-Key header.
INGEST_KEY = os.getenv("DEFENCEAI_INGEST_KEY", "")

# Names of planted lure files. Touching one of these is a strong signal.
HONEYTOKEN_MARKERS = (
    "backup_db.sql",
    ".aws/credentials",
    "id_rsa_backup",
    "customers.csv",
    "/.env",
)
