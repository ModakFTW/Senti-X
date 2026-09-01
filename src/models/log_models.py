"""Pydantic v2 input models for normalised Zeek log records."""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class ConnLog(BaseModel):
    model_config = {"populate_by_name": True}
    ts: float
    orig_h: str = Field(alias="id.orig_h")
    orig_p: int = Field(alias="id.orig_p")
    resp_h: str = Field(alias="id.resp_h")
    resp_p: int = Field(alias="id.resp_p")
    proto: Optional[str] = None
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None


class SSHLog(BaseModel):
    model_config = {"populate_by_name": True}
    ts: float
    orig_h: str = Field(alias="id.orig_h")
    resp_h: str = Field(alias="id.resp_h")
    resp_p: int = Field(alias="id.resp_p")
    auth_success: Optional[bool] = None
    auth_attempts: Optional[int] = None


class SSLLog(BaseModel):
    model_config = {"populate_by_name": True}
    ts: float
    orig_h: str = Field(alias="id.orig_h")
    resp_h: str = Field(alias="id.resp_h")
    resp_p: int = Field(alias="id.resp_p")
    version: Optional[str] = None
    cipher: Optional[str] = None
    validation_status: Optional[str] = None
    server_name: Optional[str] = None
    ja3: Optional[str] = None
    duration: Optional[float] = None


class LogBundle(BaseModel):
    conn_logs: list[ConnLog] = []
    ssh_logs: list[SSHLog] = []
    ssl_logs: list[SSLLog] = []

    @model_validator(mode="after")
    def at_least_one_non_empty(self) -> "LogBundle":
        if not self.conn_logs and not self.ssh_logs and not self.ssl_logs:
            raise ValueError(
                "LogBundle must contain at least one non-empty log list."
            )
        return self
