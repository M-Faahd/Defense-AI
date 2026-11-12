"""Helpers shared by the decoys: send events, read deception state."""
import asyncio
import os
from datetime import datetime, timezone

import httpx

BACKEND = os.getenv("DEFENCEAI_BACKEND", "http://127.0.0.1:8000")
_key = os.getenv("DEFENCEAI_INGEST_KEY", "")
HEADERS = {"X-Ingest-Key": _key} if _key else {}

DEFAULT_STATE = {"accept_login": False, "files": {}, "unlocked": []}


def clip(value, limit=480):
    return None if value is None else str(value)[:limit]


async def emit(client, ip, session_id, event_type,
               username=None, command=None, details=None):
    """Send one event. Never raises: a decoy must keep running."""
    payload = {
        "source_ip": ip,
        "session_id": session_id,
        "event_type": event_type,
        "username": clip(username, 90),
        "command": clip(command),
        "details": clip(details),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        await client.post(f"{BACKEND}/api/events", json=payload,
                          headers=HEADERS, timeout=3)
    except httpx.HTTPError as exc:
        print("backend unreachable:", type(exc).__name__)


async def get_state(client, ip):
    try:
        r = await client.get(f"{BACKEND}/api/deception/state",
                             params={"ip": ip}, headers=HEADERS, timeout=3)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return dict(DEFAULT_STATE)


async def heartbeat_loop(client, name, kind, port):
    while True:
        try:
            await client.post(f"{BACKEND}/api/decoys/heartbeat",
                              json={"name": name, "kind": kind,
                                    "port": port},
                              headers=HEADERS, timeout=3)
        except httpx.HTTPError:
            pass
        await asyncio.sleep(10)
