"""Version 1 of the collector wire format."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .policy_wire import Subject

INGEST_PATH = "/v1/http-events"
MAX_BYTES = 32768
APP_PATTERN = r"[a-z][a-z0-9-]{0,47}"
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
RequestId = Annotated[str, Field(pattern=UUID_PATTERN)]


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class HttpEvent(WireModel):
    request_id: RequestId
    timestamp: int = Field(ge=0)
    route: str = Field(
        max_length=160,
        pattern=r"^(?:unmatched|pre_router|/(?:[A-Za-z0-9_-]+|\{[A-Za-z_][A-Za-z0-9_]*(?::[a-z]+)?\})?(?:/(?:[A-Za-z0-9_-]+|\{[A-Za-z_][A-Za-z0-9_]*(?::[a-z]+)?\}))*/*)$",
    )
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "OTHER"]
    status: int = Field(ge=100, le=599)
    duration_ms: float = Field(ge=0, le=86400000)
    auth: Literal["none", "anonymous", "authenticated", "denied", "authorization_denied",
                  "origin_denied", "rate_limited"]
    subject: Subject | None = None
    mitigation_applied: bool | None = None
    policy_revision: int | None = Field(default=None, ge=1, le=2**53 - 1)
    policy_unrestricted: bool | None = None

    @model_validator(mode="after")
    def verified_attribution(self):
        if (self.auth == "authorization_denied" and (not self.subject or self.status not in (403, 404))
                or self.subject and not (self.auth in {"authenticated", "authorization_denied"}
                                         or (self.auth == "rate_limited" and self.status == 429)
                                         or (self.auth == "denied" and self.status == 403))):
            raise ValueError("Attribution requires an authenticated request")
        if (self.policy_revision is not None and not self.subject
                or self.mitigation_applied and (self.policy_revision is None or self.status not in (403, 429))
                or self.policy_unrestricted is not None and self.policy_revision is None
                or self.policy_unrestricted and self.mitigation_applied):
            raise ValueError("Policy observations require consistent scoped attribution")
        return self


class DeliveryHealth(WireModel):
    queued: int = Field(ge=0, le=512)
    sent: int = Field(ge=0, le=2**53 - 1)
    dropped: int = Field(ge=0, le=2**53 - 1)
    retries: int = Field(ge=0, le=2**53 - 1)
    failed_batches: int = Field(ge=0, le=2**53 - 1)


class Batch(WireModel):
    version: int = Field(ge=1, le=1)
    events: list[HttpEvent] = Field(max_length=32)
    delivery: DeliveryHealth
