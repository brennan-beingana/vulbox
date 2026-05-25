"""Tests for GeminiProvider's primary→backup failover (no real API calls)."""
import os
from unittest.mock import MagicMock, patch

os.environ["VULBOX_DEV_MODE"] = "true"

from google.genai import errors

from app.services.llm_provider import GeminiProvider


def _resp(text):
    r = MagicMock()
    r.text = text
    return r


def _fake_settings(primary="gemini-2.5-flash", backup="gemini-2.5-flash-lite"):
    s = MagicMock()
    s.gemini_api_key = "AIza-test"
    s.llm_model_primary = primary
    s.llm_model_backup = backup
    s.llm_max_tokens = 1024
    s.llm_timeout_secs = 30
    return s


def _client_with(side_effect):
    """Return a fake genai.Client whose models.generate_content uses side_effect."""
    client = MagicMock()
    client.models.generate_content.side_effect = side_effect
    return client


def test_returns_none_without_key():
    s = _fake_settings()
    s.gemini_api_key = ""
    with patch("app.services.llm_provider.settings", s):
        assert GeminiProvider.generate_json("sys", "user") is None


def test_primary_success():
    s = _fake_settings()
    client = _client_with(lambda **kw: _resp('{"ok": true}'))
    with patch("app.services.llm_provider.settings", s), \
         patch("google.genai.Client", return_value=client):
        out = GeminiProvider.generate_json("sys", "user")
    assert out == {"ok": True}
    # Only the primary model was needed.
    assert client.models.generate_content.call_count == 1
    assert client.models.generate_content.call_args.kwargs["model"] == "gemini-2.5-flash"


def test_falls_back_to_backup_on_rate_limit():
    s = _fake_settings()

    def side_effect(**kw):
        if kw["model"] == "gemini-2.5-flash":
            raise errors.ClientError(429, {"error": {"message": "RESOURCE_EXHAUSTED"}})
        return _resp('{"ok": "backup"}')

    client = _client_with(side_effect)
    with patch("app.services.llm_provider.settings", s), \
         patch("google.genai.Client", return_value=client):
        out = GeminiProvider.generate_json("sys", "user")
    assert out == {"ok": "backup"}
    assert client.models.generate_content.call_count == 2


def test_returns_none_when_both_models_fail():
    s = _fake_settings()

    def side_effect(**kw):
        raise errors.ServerError(500, {"error": {"message": "boom"}})

    client = _client_with(side_effect)
    with patch("app.services.llm_provider.settings", s), \
         patch("google.genai.Client", return_value=client):
        out = GeminiProvider.generate_json("sys", "user")
    assert out is None
    assert client.models.generate_content.call_count == 2


def test_falls_through_on_unparseable_then_succeeds():
    s = _fake_settings()

    def side_effect(**kw):
        if kw["model"] == "gemini-2.5-flash":
            return _resp("not json at all")
        return _resp('{"ok": 1}')

    client = _client_with(side_effect)
    with patch("app.services.llm_provider.settings", s), \
         patch("google.genai.Client", return_value=client):
        out = GeminiProvider.generate_json("sys", "user")
    assert out == {"ok": 1}
    assert client.models.generate_content.call_count == 2
