from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import Out


class DashboardOut(BaseModel):
    usuarios: dict
    seguridad: dict
    salud_sistema: dict
    motores_ia: dict


class AdminUserOut(Out):
    id: str
    email: str
    full_name: str
    role: str
    status: str
    plan: str
    totp_enabled: bool
    last_login_at: datetime | None
    created_at: datetime


class UserStatusIn(BaseModel):
    status: Literal["active", "suspended"]
    reason: str = Field(min_length=3, max_length=200)


class RoleChangeIn(BaseModel):
    role: Literal["user", "supervisor", "admin", "super_admin"]
    reason: str = Field(min_length=3, max_length=200)


class AlertOut(Out):
    id: str
    user_id: str | None
    category: str
    severity: str
    title: str
    description: str
    status: str
    engine: str | None
    created_at: datetime


class AlertResolveIn(BaseModel):
    feedback: Literal["true_positive", "false_positive"]
    note: str | None = Field(None, max_length=300)


class BlockIpIn(BaseModel):
    ip: str = Field(min_length=7, max_length=45)
    reason: str = Field(min_length=3, max_length=160)
    hours: int | None = Field(None, ge=1, le=8760)


class AuditOut(BaseModel):
    id: int
    ts: datetime
    actor_id: str | None
    action: str
    level: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    detail: dict


class RecommendationOut(Out):
    id: str
    area: str
    setting_key: str
    current_value: dict
    proposed_value: dict
    rationale: str
    evidence: dict
    expert_review: str | None
    status: str
    created_at: datetime


class DecisionIn(BaseModel):
    decision: Literal["approve", "reject", "modify"]
    modified_value: dict | None = None
    note: str | None = Field(None, max_length=300)


class ThresholdIn(BaseModel):
    hr_min: int | None = Field(None, ge=20, le=100)
    hr_max: int | None = Field(None, ge=60, le=250)
    spo2_min: int | None = Field(None, ge=70, le=100)
    reason: str = Field(min_length=3, max_length=300)
