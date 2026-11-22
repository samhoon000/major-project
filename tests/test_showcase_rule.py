from backend.telemetry.protection_policy import Policy, attributed_proposal
from backend.telemetry.rules import SHOWCASE_APP, SHOWCASE_ROUTE, SHOWCASE_RULE, configured_rules, match_signal


def test_showcase_threshold_requires_disposable_staging_scope(monkeypatch):
    subject = "s1_" + "a" * 64
    def rule():
        return next(item for item in configured_rules() if item.id == SHOWCASE_RULE)

    monkeypatch.delenv("HTTP_SHOWCASE_SUBJECT", raising=False)
    assert not rule().enabled
    monkeypatch.setenv("HTTP_SHOWCASE_SUBJECT", subject)
    active = rule()
    assert active.enabled and active.threshold == 3
    event = {"app": SHOWCASE_APP, "subject": subject, "route": SHOWCASE_ROUTE,
             "method": "POST", "status": 204, "auth": "authenticated"}
    assert match_signal(active, event)
    for override in ({"app": "northfield-prod"}, {"subject": "s1_" + "b" * 64},
                     {"route": "/api/courses/{course_id}/enroll"}, {"status": 429}):
        assert not match_signal(active, event | override)

    alert = {"app": SHOWCASE_APP, "rule": SHOWCASE_RULE, "status": "open",
             "evidence": {"subject": subject, "route": SHOWCASE_ROUTE, "method": "POST",
                          "quality": "verified_subject", "observed_count": 3, "requests": [event]}}
    assert attributed_proposal(alert, [], Policy()) is None
    policy = Policy(showcase_subject=subject)
    proposal = attributed_proposal(alert, [], policy)
    assert proposal.action == "RATE_LIMIT" and proposal.subject == subject
    assert attributed_proposal(alert | {"app": "northfield-prod"}, [], policy) is None
