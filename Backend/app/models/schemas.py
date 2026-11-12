from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    source_ip: str = "127.0.0.1"
    session_id: str = Field(min_length=1, max_length=100)
    event_type: Literal[
        "connection",
        "login_attempt",
        "login_success",
        "command",
        "file_download",
        "service_scan",
        "resource_discovery",
        "web_request",
    ]
    username: str | None = Field(default=None, max_length=100)
    command: str | None = Field(default=None, max_length=500)
    details: str | None = Field(default=None, max_length=500)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class Heartbeat(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    kind: str = Field(max_length=30)
    port: int | None = None
