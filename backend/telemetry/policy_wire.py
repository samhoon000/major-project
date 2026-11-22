"""Signed policy protocol. This file is shared verbatim with the Northfield checkout."""

import hashlib
import hmac
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SYNC_PATH = "/v1/policy/sync"
MAX_BYTES = 16384
MAX_LIFETIME = 120
APP = r"^[a-z][a-z0-9-]{0,39}-(?:staging|prod)$"
UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
SUBJECT = r"^s1_[0-9a-f]{64}$"
Id = Annotated[str, Field(pattern=UUID)]
Subject = Annotated[str, Field(pattern=SUBJECT)]
App = Annotated[str, Field(pattern=APP)]
Environment = Literal["staging", "production"]
Route = Literal[
    "/api/courses/{course_id}/enroll", "/api/courses/{course_id}/access",
    "/api/assignments/{assignment_id}/submit",
]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Rule(Model):
    id: Id
    subject: Subject
    method: Literal["POST"]
    route: Route
    action: Literal["rate_limit", "block"]
    requests_per_minute: int = Field(ge=1, le=120)
    expires: int = Field(ge=0)


def channel_environment(app):
    return "production" if app.endswith("-prod") else "staging"


class Snapshot(Model):
    version: int = Field(ge=1, le=1)
    app: App
    environment: Environment
    id: Id
    revision: int = Field(ge=1, le=2**53 - 1)
    created: int = Field(ge=0)
    expires: int = Field(ge=0)
    enabled: bool
    rules: list[Rule] = Field(max_length=16)

    @model_validator(mode="after")
    def bounded(self):
        slots = {(rule.subject, rule.method, rule.route) for rule in self.rules}
        if (self.environment != channel_environment(self.app)
                or (self.environment == "production" and any(rule.action != "rate_limit" for rule in self.rules))
                or not 0 < self.expires - self.created <= MAX_LIFETIME
                or (not self.enabled and self.rules) or len(slots) != len(self.rules)
                or len({rule.id for rule in self.rules}) != len(self.rules)
                or any(not self.created < rule.expires <= self.expires for rule in self.rules)):
            raise ValueError("Invalid policy lifetime or scope")
        return self


class Receipt(Model):
    id: Id
    revision: int = Field(ge=1, le=2**53 - 1)
    policy_id: Id
    rule_id: Id | None = None
    request_id: Id | None = None
    outcome: Literal["applied", "disabled", "rate_limited", "blocked"]
    timestamp: int = Field(ge=0)

    @model_validator(mode="after")
    def event_scope(self):
        action = self.outcome in {"rate_limited", "blocked"}
        if action != (self.rule_id is not None and self.request_id is not None):
            raise ValueError("Invalid receipt scope")
        if not action and (self.rule_id or self.request_id):
            raise ValueError("Invalid receipt scope")
        return self


class Sync(Model):
    version: int = Field(ge=1, le=1)
    app: App
    environment: Environment
    nonce: Id
    timestamp: int = Field(ge=0)
    receipts: list[Receipt] = Field(max_length=16)
    errors: int = Field(default=0, ge=0, le=2**53 - 1)

    @model_validator(mode="after")
    def bound_channel(self):
        if self.environment != channel_environment(self.app):
            raise ValueError("Policy channel does not match the environment")
        return self


def sign(key, purpose, nonce, body):
    message = f"sentinel-policy-v1\n{purpose}\n{nonce}\n".encode("ascii") + body
    return hmac.new(key, message, hashlib.sha256).hexdigest()
