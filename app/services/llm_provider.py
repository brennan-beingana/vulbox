"""Google Gemini provider with a primary→backup failover chain.

A single API key drives two models: ``llm_model_primary`` serves every call,
and ``llm_model_backup`` is the failover used when the primary raises an API
error (notably 429 ``RESOURCE_EXHAUSTED`` rate limits), a server error, or
times out. Both models share one ``genai.Client``.

The provider is deliberately thin and provider-shaped so the remediation
service stays agnostic: it takes a system prompt, a user prompt, and a schema,
and returns parsed JSON (a ``dict``) or ``None``. Every failure mode —
missing SDK, missing key, transport error, malformed response — collapses to
``None`` so callers can fall back to static rules. It never raises.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class GeminiProvider:
    """Generate strict-JSON completions via Gemini, with backup-model failover."""

    @staticmethod
    def is_available() -> bool:
        return bool(settings.gemini_api_key)

    @staticmethod
    def generate_json(
        system_prompt: str,
        user_prompt: str,
        schema: Optional[dict] = None,
    ) -> Optional[dict]:
        """Return parsed JSON from Gemini, or ``None`` on any failure.

        Tries the primary model first; on an API/transport error or timeout,
        retries once on the backup model. ``schema`` (a JSON-schema dict) is
        passed as ``response_schema`` to constrain the output when supplied.
        """
        try:
            from google import genai
            from google.genai import errors, types
        except ImportError:
            logger.warning("google-genai SDK not installed; skipping LLM call")
            return None

        if not settings.gemini_api_key:
            return None

        try:
            client = genai.Client(api_key=settings.gemini_api_key)
        except Exception as exc:  # noqa: BLE001 — bad key/config → fallback
            logger.warning("Gemini client init failed", extra={"err": str(exc)})
            return None

        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            response_mime_type="application/json",
            response_schema=schema,
            max_output_tokens=settings.llm_max_tokens,
            temperature=0.2,
            # SDK takes the request timeout in milliseconds.
            http_options=types.HttpOptions(timeout=settings.llm_timeout_secs * 1000),
        )

        for model in (settings.llm_model_primary, settings.llm_model_backup):
            try:
                resp = client.models.generate_content(
                    model=model,
                    contents=user_prompt,
                    config=config,
                )
            except (errors.APIError, Exception) as exc:  # noqa: BLE001
                # APIError covers 4xx (incl. 429 RESOURCE_EXHAUSTED) and 5xx;
                # the broad arm also catches transport/timeout errors. Either
                # way we try the next model in the chain.
                code = getattr(exc, "code", None)
                logger.warning(
                    "Gemini call failed; trying next model",
                    extra={"model": model, "code": code, "err": str(exc)},
                )
                continue

            parsed = _parse_json_response(getattr(resp, "text", "") or "")
            if parsed is not None:
                logger.info("Gemini call succeeded", extra={"model": model})
                return parsed
            logger.warning(
                "Gemini response was not valid JSON; trying next model",
                extra={"model": model},
            )

        return None


def _parse_json_response(raw: str) -> Optional[dict]:
    """Extract a JSON object from the model's response.

    JSON mode normally yields a clean object, but we keep the fence-strip and
    first-object salvage as belt-and-braces for the backup model.
    """
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None
