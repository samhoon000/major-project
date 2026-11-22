"""Explainable policies for proposals only. No request or firewall integration."""

import os
import re
import tomllib
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .rules import RULE_NAMES, SHOWCASE_APP, SHOWCASE_COUNT, SHOWCASE_ROUTE, SHOWCASE_RULE
from .schemas import APP_PATTERN
from .policy_wire import APP, Route, SUBJECT, channel_environment

Action = Literal["ALLOW", "MONITOR", "RATE_LIMIT", "CHALLENGE", "BLOCK"]
MAX_DURATION = 300
PROTECTED_ROUTES = ("/admin", "/api/admin", "/dashboard", "/api/telemetry", "/api/auth/logout")
AUTH_RULES = ("login_failures", "authorization_denials")
VERIFIED_QUALITY = {"verified_subject", "verified_staging_subject"}


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Exemptions(PolicyModel):
    allowlisted: bool = False
    routes: list[str] = Field(default_factory=list, max_length=32)
    rules: list[str] = Field(default_factory=list, max_length=len(RULE_NAMES))

    @field_validator("routes")
    @classmethod
    def safe_routes(cls, routes):
        if any(not re.fullmatch(r"/[a-zA-Z0-9_/{\}-]{1,159}", route) for route in routes):
            raise ValueError("Use safe route templates without queries")
        return routes

    @field_validator("rules")
    @classmethod
    def known_rules(cls, rules):
        if set(rules) - RULE_NAMES.keys():
            raise ValueError("Unknown detection rule")
        return rules


class Policy(PolicyModel):
    showcase_subject: str | None = Field(None, pattern=SUBJECT)
    window_seconds: int = Field(120, ge=60, le=300)
    cooldown_seconds: int = Field(120, ge=30, le=600)
    minimum_burst: int = Field(40, ge=31, le=10000)
    minimum_burst_duration_seconds: int = Field(3, ge=1, le=10)
    minimum_login_denials: int = Field(8, ge=5, le=1000)
    minimum_authorization_denials: int = Field(5, ge=5, le=1000)
    staging_minimum_burst: int | None = Field(None, ge=4, le=10000)
    staging_minimum_authorization_denials: int | None = Field(None, ge=2, le=1000)
    minimum_unmatched: int = Field(8, ge=8, le=1000)
    rate_limit_seconds: int = Field(60, ge=1, le=MAX_DURATION)
    block_seconds: int = Field(120, ge=1, le=MAX_DURATION)
    proposed_requests_per_minute: int = Field(60, ge=1, le=10000)
    applications: dict[str, Exemptions] = Field(default_factory=dict, max_length=32)

    @field_validator("applications")
    @classmethod
    def application_ids(cls, applications):
        if any(not re.fullmatch(APP_PATTERN, app) for app in applications):
            raise ValueError("Invalid application deployment identifier")
        return applications


class Proposal(BaseModel):
    action: Action
    severity: str
    route: str | None
    reason: str
    duration_seconds: int = 0
    subject: str | None = None
    supporting: list[dict]


def load_policy():
    path = os.getenv("HTTP_PROTECTION_CONFIG")
    if not path:
        return Policy()
    with open(path, "rb") as config:
        return Policy.model_validate(tomllib.load(config))


def paths(alert):
    evidence = alert["evidence"]
    return {item["route"] for item in evidence["requests"]} | {evidence["route"]}


def protected(route):
    return route and any(route == prefix or route.startswith(prefix + "/") for prefix in PROTECTED_ROUTES)


def exempt(alert, policy):
    exclusions = policy.applications.get(alert["app"])
    route = alert["evidence"]["route"]
    known = {value for value in paths(alert) if value and value.startswith("/")}
    if protected(route) or (known and all(protected(value) for value in known)):
        return "Built-in administrative or operator exemption."
    if exclusions:
        if exclusions.allowlisted:
            return "This application deployment is allowlisted."
        if alert["rule"] in exclusions.rules:
            return "This rule is exempt for this application."
        if route in exclusions.routes or (known and known <= set(exclusions.routes)):
            return "This route is exempt for this application."
    return None


def scope_available(alerts, route, policy):
    if route:
        if protected(route):
            return False
        exclusions = policy.applications.get(alerts[0]["app"])
        return not exclusions or route not in exclusions.routes
    return False


def eligible(alert, policy):
    if alert["evidence"]["quality"] != "aggregate_observation" or exempt(alert, policy):
        return False
    exclusions = policy.applications.get(alert["app"])
    return not any(protected(route) or (exclusions and route in exclusions.routes) for route in paths(alert))


def attributed_proposal(trigger, recent, policy):
    evidence = trigger["evidence"]
    subject, route = evidence.get("subject"), evidence["route"]
    if trigger["rule"] == SHOWCASE_RULE:
        if (trigger["app"] == SHOWCASE_APP and subject and subject == policy.showcase_subject
                and route == SHOWCASE_ROUTE and evidence.get("method") == "POST"
                and evidence["quality"] in VERIFIED_QUALITY and evidence["observed_count"] >= SHOWCASE_COUNT
                and trigger["status"] in {"open", "acknowledged"} and not exempt(trigger, policy)):
            return Proposal(action="RATE_LIMIT", severity="low", route=route, subject=subject,
                            supporting=[trigger], duration_seconds=policy.rate_limit_seconds,
                            reason="Successful requests exceeded the configured disposable staging threshold.")
        return None
    if (trigger["rule"] not in {"route_burst", "authorization_denials"} or not subject
            or not re.fullmatch(APP, trigger["app"]) or evidence.get("method") != "POST"
            or route not in get_args(Route)):
        return None
    scoped = [row for row in recent if row["app"] == trigger["app"]
              and row["status"] in {"open", "acknowledged"}
              and trigger["last_seen"] - policy.window_seconds * 1000 <= row["last_seen"] <= trigger["last_seen"]
              and row["evidence"].get("quality") in VERIFIED_QUALITY
              and row["evidence"].get("subject") == subject and row["evidence"].get("method") == "POST"
              and row["evidence"]["route"] == route and not exempt(row, policy)]
    burst = next((row for row in scoped if row["rule"] == "route_burst"), None)
    denial = next((row for row in scoped if row["rule"] == "authorization_denials"), None)
    if not burst or not denial or trigger["id"] not in (burst["id"], denial["id"]):
        return None
    arrivals = [request["received_at"] for request in burst["evidence"]["requests"]]
    staging = channel_environment(trigger["app"]) == "staging"
    minimum_burst = (policy.staging_minimum_burst if staging else None) or policy.minimum_burst
    minimum_denials = (policy.staging_minimum_authorization_denials if staging else None) or policy.minimum_authorization_denials
    duration = max(arrivals) - min(arrivals) if staging and arrivals else burst["evidence"].get("occurrence_span_ms", 0)
    if (burst["evidence"]["observed_count"] < minimum_burst
            or duration < policy.minimum_burst_duration_seconds * 1000
            or denial["evidence"]["observed_count"] < minimum_denials
            or not any(200 <= item["status"] < 300 for item in burst["evidence"]["requests"])):
        return None
    block = staging and denial["evidence"]["observed_count"] >= max(8, minimum_denials)
    return Proposal(action="BLOCK" if block else "RATE_LIMIT", severity="high" if block else "medium",
                    route=route, subject=subject, supporting=[burst, denial],
                    duration_seconds=policy.block_seconds if block else policy.rate_limit_seconds,
                    reason="A sustained burst with successful requests and explicit authorization denials "
                           "shared a verified client identity, method, and route.")


def evaluate(trigger, recent, policy):
    route = trigger["evidence"]["route"]
    if reason := exempt(trigger, policy):
        return Proposal(action="ALLOW", severity="info", route=route, reason=reason, supporting=[trigger])
    if proposal := attributed_proposal(trigger, recent, policy):
        return proposal

    related = [alert for alert in recent if alert["app"] == trigger["app"]
               and alert["status"] in {"open", "acknowledged"}
               and trigger["last_seen"] - policy.window_seconds * 1000 <= alert["last_seen"] <= trigger["last_seen"]
               and eligible(alert, policy)]
    grouped = {rule: [alert for alert in related if alert["rule"] == rule] for rule in RULE_NAMES}
    thresholds = {"login_failures": policy.minimum_login_denials,
                  "authorization_denials": policy.minimum_authorization_denials,
                  "route_probing": policy.minimum_unmatched}
    triad = [next((alert for alert in grouped[rule] if alert["evidence"]["observed_count"] >= minimum), None)
             for rule, minimum in thresholds.items()]
    if all(triad) and any(alert["id"] == trigger["id"] for alert in triad):
        login_route = triad[0]["evidence"]["route"]
        if scope_available(triad, login_route, policy):
            return Proposal(action="BLOCK", severity="high", route=login_route, duration_seconds=policy.block_seconds,
                            reason="Explicit login and authorization denials plus unmatched-route probing met three "
                                   "distinct thresholds for this application. The login route is a shadow scope.",
                            supporting=triad)

    if trigger["rule"] in (*AUTH_RULES, "route_burst"):
        for burst in grouped["route_burst"]:
            burst_route = burst["evidence"]["route"]
            arrivals = [item["received_at"] for item in burst["evidence"]["requests"]]
            if (not scope_available([burst], burst_route, policy)
                    or burst["evidence"]["observed_count"] < policy.minimum_burst
                    or not arrivals or max(arrivals) - min(arrivals) < policy.minimum_burst_duration_seconds * 1000):
                continue
            for rule in AUTH_RULES:
                for denial in grouped[rule]:
                    minimum = thresholds[rule]
                    evidence = denial["evidence"]
                    same_route = (evidence["observed_count"] if evidence["route"] == burst_route else
                                  sum(item["route"] == burst_route for item in evidence["requests"]))
                    if (evidence["observed_count"] >= minimum and same_route >= min(minimum, 5)
                            and trigger["id"] in (burst["id"], denial["id"])):
                        return Proposal(
                            action="RATE_LIMIT", severity="medium", route=burst_route,
                            duration_seconds=policy.rate_limit_seconds, supporting=[burst, denial],
                            reason="A sustained request burst and explicit access or login denials involved the same "
                                   "route. The limit is a route-scoped shadow proposal.",
                        )
    return Proposal(action="MONITOR", severity=trigger["severity"], route=route, supporting=[trigger],
                    reason="Recorded for review. The evidence does not meet the corroboration requirements "
                           "for a block or rate-limit proposal.")
