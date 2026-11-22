"""Configurable alert-only rules for authenticated HTTP telemetry."""

import os
import re
import tomllib
from dataclasses import dataclass, replace
from typing import get_args

from .policy_wire import Route, SUBJECT

SHOWCASE_APP = "northfield-staging"
SHOWCASE_ROUTE = "/api/courses/{course_id}/access"
SHOWCASE_RULE = "showcase_course_access"
SHOWCASE_COUNT = 3
SHOWCASE_WINDOW = 8


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    threshold: int
    window_seconds: int
    cooldown_seconds: int = 120
    enabled: bool = True
    minimum_samples: int = 0
    ratio_percent: int = 0
    baseline_seconds: int = 0
    subject: str | None = None


DEFAULT_RULES = (
    Rule("login_failures", "Repeated login failures", "medium", 5, 60),
    Rule("route_burst", "Route request burst", "low", 31, 10),
    Rule("authorization_denials", "Repeated authorization denials", "medium", 5, 120),
    Rule("route_probing", "Repeated unmatched routes", "low", 8, 60),
    Rule("server_errors", "Elevated server error rate", "low", 10, 60,
         minimum_samples=20, ratio_percent=50),
    Rule("traffic_spike", "Application traffic spike", "info", 100, 60,
         minimum_samples=100, ratio_percent=300, baseline_seconds=300),
    Rule("sensitive_route_frequency", "Repeated sensitive-route requests", "low", 60, 60),
    Rule("repeated_policy_rate_limits", "Repeated policy rate limits", "medium", 3, 10),
    Rule(SHOWCASE_RULE, "Showcase course-access threshold", "low", SHOWCASE_COUNT, SHOWCASE_WINDOW,
         cooldown_seconds=SHOWCASE_WINDOW, enabled=False),
)
RULE_NAMES = {rule.id: rule.name for rule in DEFAULT_RULES}
LOGIN_ROUTE = "/api/auth/login"
SENSITIVE_ROUTES = frozenset(get_args(Route))


def configured_rules():
    path = os.getenv("HTTP_DETECTION_CONFIG")
    overrides = {}
    if path:
        with open(path, "rb") as config:
            overrides = tomllib.load(config)
    if unknown := overrides.keys() - RULE_NAMES.keys():
        raise ValueError(f"Unknown HTTP detection rules: {', '.join(sorted(unknown))}")
    rules = []
    for rule in DEFAULT_RULES:
        if rule.id == SHOWCASE_RULE:
            subject = os.getenv("HTTP_SHOWCASE_SUBJECT", "")
            if subject and not re.fullmatch(SUBJECT, subject):
                raise ValueError("Invalid showcase subject")
            rules.append(replace(rule, enabled=bool(subject), subject=subject or None))
            continue
        supplied = overrides.get(rule.id, {})
        limits = {"threshold": (1, 100000), "window_seconds": (1, 600), "cooldown_seconds": (1, 3600)}
        if rule.minimum_samples:
            limits["minimum_samples"] = (1, 100000)
            limits["ratio_percent"] = (1, 100 if rule.id == "server_errors" else 10000)
        if rule.baseline_seconds:
            limits["baseline_seconds"] = (1, 3600)
        if not isinstance(supplied, dict) or supplied.keys() - (limits.keys() | {"enabled"}):
            raise ValueError(f"Invalid HTTP detection settings for {rule.id}")
        for name, value in supplied.items():
            if name == "enabled":
                valid = type(value) is bool
            else:
                low, high = limits[name]
                valid = type(value) is int and low <= value <= high
            if not valid:
                raise ValueError(f"Invalid HTTP detection value for {rule.id}.{name}")
        rules.append(replace(rule, **supplied))
    return tuple(rules)


@dataclass(frozen=True)
class Signal:
    route: str | None
    condition: str
    parameters: tuple
    explanation: str
    subject: str | None = None


def match_signal(rule, event):
    subject = event.get("subject")
    if (rule.id == SHOWCASE_RULE and rule.subject and subject == rule.subject
            and (event["app"], event["route"], event["method"], event["status"], event["auth"])
            == (SHOWCASE_APP, SHOWCASE_ROUTE, "POST", 204, "authenticated")):
        return Signal(SHOWCASE_ROUTE, "route=? AND method='POST' AND status=204 AND auth='authenticated' "
                      "AND json_extract(payload,'$.subject')=?", (SHOWCASE_ROUTE, subject),
                      "Three successful course requests crossed the disposable staging threshold.", subject)
    if (subject and rule.id == "sensitive_route_frequency" and event["status"] != 429
            and event["method"] == "POST" and event["route"] in SENSITIVE_ROUTES):
        return Signal(event["route"], "route=? AND method=? AND status!=429 AND json_extract(payload,'$.subject')=?",
                      (event["route"], event["method"], subject),
                      "Repeated requests from one authenticated subject to a sensitive write route.", subject)
    if (subject and rule.id == "repeated_policy_rate_limits" and event["status"] == 429
            and event.get("mitigation_applied")):
        return Signal(event["route"], "route=? AND method=? AND json_extract(payload,'$.subject')=? "
                      "AND status=429 AND json_extract(payload,'$.mitigation_applied')=1",
                      (event["route"], event["method"], subject),
                      "Multiple requests from one authenticated subject continued to return policy-issued HTTP 429.", subject)
    if rule.id == "login_failures" and (
        event["route"], event["method"], event["status"], event["auth"]
    ) == (LOGIN_ROUTE, "POST", 401, "denied"):
        return Signal(LOGIN_ROUTE, "route=? AND method='POST' AND status=401 AND auth='denied'",
                      (LOGIN_ROUTE,), "Repeated explicit login denials across this application.")
    if rule.id == "route_burst" and event["route"].startswith("/"):
        if subject:
            return Signal(event["route"], "route=? AND method=? AND json_extract(payload,'$.subject')=?",
                          (event["route"], event["method"], subject),
                          "Request volume exceeded the threshold for this authenticated subject and route.", subject)
        return Signal(event["route"], "route=? AND json_extract(payload,'$.subject') IS NULL", (event["route"],),
                      "Request volume exceeded the threshold for this route across callers.")
    explicit = ((event["status"] == 403 and event["auth"] == "denied")
                or event["status"] in (403, 404) and event["auth"] == "authorization_denied")
    if rule.id == "authorization_denials" and explicit:
        if subject:
            return Signal(event["route"], "((status=403 AND auth='denied') OR "
                          "(status IN (403,404) AND auth='authorization_denied')) AND route=? AND method=? "
                          "AND json_extract(payload,'$.subject')=?", (event["route"], event["method"], subject),
                          "Repeated explicit access denials for this authenticated subject and route.", subject)
        return Signal(None, "status=403 AND auth='denied' AND json_extract(payload,'$.subject') IS NULL", (),
                      "Repeated explicit access denials across this application.")
    if rule.id == "route_probing" and event["route"] == "unmatched" and event["status"] in (404, 405):
        return Signal("unmatched", "route='unmatched' AND status IN (404, 405)", (),
                      "Repeated requests did not match a published route.")
    if rule.id == "server_errors" and event["status"] >= 500:
        return Signal(None, "status>=500", (), "A large share of recent requests returned server errors.")
    if rule.id == "traffic_spike":
        return Signal(None, "1=1", (), "Recent request volume exceeded the application’s preceding baseline.")
    return None
