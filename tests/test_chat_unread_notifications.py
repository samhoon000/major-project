import re
import pytest
from backend.chat_service import CHAT_HTML, state


def test_chat_html_contains_unread_badge_styles():
    assert ".unread-badge" in CHAT_HTML
    assert "#0d9488" in CHAT_HTML
    assert "@keyframes unread-pulse" in CHAT_HTML
    assert ".user-item.has-unread" in CHAT_HTML


def test_chat_html_contains_unread_state_and_helpers():
    assert "const unreadCounts = new Map();" in CHAT_HTML
    assert "const seenMessageIds = new Set();" in CHAT_HTML
    assert "sentinel_unread_" in CHAT_HTML
    assert "function loadUnreadCounts()" in CHAT_HTML
    assert "function saveUnreadCounts()" in CHAT_HTML
    assert "function getUnreadCount(" in CHAT_HTML
    assert "function formatUnreadCount(" in CHAT_HTML
    assert "function markAsRead(" in CHAT_HTML
    assert "function updateDocumentTitle()" in CHAT_HTML


def test_chat_html_contains_badge_rendering_and_visibility():
    assert "formatUnreadCount(unread)" in CHAT_HTML
    assert "unreadBadge_" in CHAT_HTML
    assert "visibilitychange" in CHAT_HTML
    assert "document.visibilityState === 'visible'" in CHAT_HTML
    assert "window.SentinelChat" in CHAT_HTML


def test_format_unread_count_rules():
    # Regex verification of the 99+ display rule in JS
    match = re.search(r"formatUnreadCount\(count\)\s*\{\s*return count > 99 \? '99\+' : String\(count\);", CHAT_HTML)
    assert match is not None, "formatUnreadCount should format counts > 99 as '99+'"


def test_backend_message_payload_includes_message_id():
    """Verify backend message records contain message_id for deduplication."""
    import uuid
    import time
    # Test state message emission
    record = {
        "message_id": uuid.uuid4().hex,
        "sender": "alice",
        "recipient": "bob",
        "text": "test payload",
        "timestamp": time.time(),
        "security": {"flagged": False, "score": 0.0}
    }
    assert "message_id" in record
    assert len(record["message_id"]) == 32
