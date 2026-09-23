"""SENTINEL defense — Config C: Config B + gate the directive signal on consequence.

ENCODED_DIRECTIVE_FROM_UNTRUSTED now only fires on actions that are consequential,
outbound, or a state mutation. Plain reads/searches/lookups/responds never fire it.
Everything else is byte-identical to Config B.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import re
from urllib.parse import unquote

from app.models import CandidateAction, DefenseDecision, DefenseRequest

STATUS_CONSEQUENTIAL: dict[str, set[str]] = {
    "ticket_update": {"closed", "resolved"},
    "incident_update": {"closed"},
}

PREREQUISITES: dict[str, list[str]] = {
    "payment_execute": ["payment_confirm"],
    "remediation_execute": ["remediation_prepare"],
}

SENSITIVE = {"confidential", "restricted"}
UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}

_NON_ALNUM = re.compile(r"[^a-z0-9]")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
MAX_SCAN_CHARS = 200_000

CALL_RE = re.compile(r"\bcall\s+([a-z][a-z0-9_]{1,63})\s+with\s+(?=\{)", re.IGNORECASE)
REMEMBER_RE = re.compile(r"^[ \t]*(?:please[ \t]+)?remember[ \t]*:[ \t]*(\S.*)$", re.IGNORECASE | re.MULTILINE)


def normalize(text: str) -> str:
    return _NON_ALNUM.sub("", text.lower())


def _decode_b64_tokens(text: str) -> str:
    decoded = []
    for token in _B64_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded.append(base64.b64decode(padded, validate=True).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            continue
    return "\n".join(decoded)


def _decode_hex_tokens(text: str) -> str:
    decoded = []
    for token in _HEX_TOKEN.findall(text):
        try:
            decoded.append(bytes.fromhex(token).decode("utf-8", "ignore"))
        except ValueError:
            continue
    return "\n".join(decoded)


def text_variants(text: str) -> list[tuple[str, str]]:
    text = text[:MAX_SCAN_CHARS]
    return [
        ("plain", text),
        ("url", unquote(text)),
        ("base64", _decode_b64_tokens(text)),
        ("hex", _decode_hex_tokens(text)),
        ("rot13", codecs.decode(text, "rot13")),
        ("reversed", text[::-1]),
    ]


def action_digest(action: CandidateAction) -> str:
    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def _action_text(action: CandidateAction) -> str:
    parts = [str(v) for v in action.arguments.values() if v is not None]
    if action.content:
        parts.append(action.content)
    return " ".join(parts)


def _sensitive_tainted_texts(request: DefenseRequest) -> list[str]:
    sensitive_ids = {record.id for record in request.provenance if record.provenance.sensitivity in SENSITIVE}
    texts = [item.content for item in request.conversation if sensitive_ids.intersection(item.provenance_ids)]
    if request.observation is not None and sensitive_ids.intersection(request.observation.provenance_ids):
        texts.append(request.observation.content)
    return texts


def _untrusted_texts(request: DefenseRequest) -> list[str]:
    untrusted_ids = {record.id for record in request.provenance if record.provenance.trust_level in UNTRUSTED}
    texts = [item.content for item in request.conversation if untrusted_ids.intersection(item.provenance_ids)]
    if request.observation is not None and untrusted_ids.intersection(request.observation.provenance_ids):
        texts.append(request.observation.content)
    return texts


def _destination_untrusted(action: CandidateAction, request: DefenseRequest) -> bool:
    if action.tool not in {"email_send", "email_draft"}:
        return False
    recipient = str(action.arguments.get("to", "")).lower()
    if not recipient or "@" not in recipient:
        return True
    domain = recipient.rsplit("@", 1)[-1]
    internal_domains = {d.lower() for d in request.policy_context.get("internal_email_domains", [])}
    return domain not in internal_domains


def _prerequisite_violation(action: CandidateAction, request: DefenseRequest) -> str | None:
    required = PREREQUISITES.get(action.tool or "")
    if not required:
        return None
    succeeded_tools = {
    tc.get("tool") if isinstance(tc, dict) else getattr(tc, "tool", None)
    for tc in request.history_digest.tool_calls
    if (tc.get("succeeded") if isinstance(tc, dict) else getattr(tc, "succeeded", False))
    }
    missing = [tool for tool in required if tool not in succeeded_tools]
    if missing:
        return f"{action.tool} attempted before required step(s) {missing} succeeded"
    return None


def _chunk(text: str, size: int) -> list[str]:
    if len(text) < size:
        return [text] if text else []
    return [text[i : i + size] for i in range(0, len(text) - size + 1, size)]


def _decode_aware_data_flow_hit(action: CandidateAction, request: DefenseRequest) -> str | None:
    outgoing = _action_text(action)
    if not outgoing:
        return None
    tainted = _sensitive_tainted_texts(request)
    if not tainted:
        return None
    tainted_tokens: set[str] = set()
    for text in tainted:
        tainted_tokens.update(_chunk(normalize(text), 8))
    if not tainted_tokens:
        return None
    for encoding, variant in text_variants(outgoing):
        haystack = normalize(variant)
        if any(token in haystack for token in tainted_tokens):
            return encoding
    return None


def _is_gated_for_directive_check(action: CandidateAction, request: DefenseRequest) -> bool:
    """Config C: ENCODED_DIRECTIVE_FROM_UNTRUSTED only applies to actions that are
    consequential, outbound, or a state mutation. Plain reads/searches/lookups/responds
    never fire it."""
    if action.type == "memory_write":
        return True
    if action.type != "tool_call":
        return False
    if action.tool in request.policy_context.get("consequential_tools", []):
        return True
    if action.tool in {"email_send", "email_draft", "payment_confirm", "payment_execute", "remediation_execute"}:
        return True
    if action.tool == "ticket_update" and action.arguments.get("status") in {"closed", "resolved"}:
        return True
    if action.tool == "incident_update" and action.arguments.get("status") == "closed":
        return True
    return False


def _encoded_directive_hit(action: CandidateAction, request: DefenseRequest) -> bool:
    if action.tool is None:
        return False
    arg_values = [str(v) for v in action.arguments.values() if v is not None and len(str(v)) >= 4]
    decoder = json.JSONDecoder()
    for source_text in _untrusted_texts(request):
        for _encoding, variant in text_variants(source_text):
            for match in CALL_RE.finditer(variant):
                if match.group(1).lower() != action.tool:
                    continue
                try:
                    obj, end = decoder.raw_decode(variant, match.end())
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(obj, dict):
                    continue
                raw_args = variant[match.end() : end]
                if any(value in raw_args for value in arg_values) or not arg_values:
                    return True
    return False
_TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{12,}")

def _secret_like_tokens(text: str) -> set[str]:
    out = set()
    for match in _TOKEN_LIKE.finditer(text):
        token = match.group(0)
        if any(c.isalpha() for c in token) and any(c.isdigit() for c in token):
            out.add(normalize(token))
    return out
def _locate_secret_spans(text: str, secret_tokens: set[str]) -> list[tuple[int, int]]:
    """Raw (start, end) spans in `text` whose normalized form exactly matches
    a known secret token. Covers the plain-encoding case only — see decide()
    for why non-plain matches still fall back to BLOCK."""
    return [m.span() for m in _TOKEN_LIKE.finditer(text) if normalize(m.group(0)) in secret_tokens]


def _redact_spans(text: str, spans: list[tuple[int, int]], placeholder: str = "[REDACTED]") -> str:
    for start, end in sorted(spans, reverse=True):  # back-to-front so earlier indices stay valid
        text = text[:start] + placeholder + text[end:]
    return text


def _redact_action_plain(action: CandidateAction, secret_tokens: set[str]) -> CandidateAction | None:
    """Redact exact-boundary secret_token matches in content/arguments.
    Returns None if nothing was actually changed."""
    updates: dict[str, object] = {}
    if action.content:
        spans = _locate_secret_spans(action.content, secret_tokens)
        if spans:
            updates["content"] = _redact_spans(action.content, spans)
    if action.arguments:
        new_args = dict(action.arguments)
        touched = False
        for key, value in new_args.items():
            if isinstance(value, str):
                spans = _locate_secret_spans(value, secret_tokens)
                if spans:
                    new_args[key] = _redact_spans(value, spans)
                    touched = True
        if touched:
            updates["arguments"] = new_args
    if not updates:
        return None
    return action.model_copy(update=updates)

def _restricted_disclosure_hit(action, request) -> tuple[str, CandidateAction | None] | None:
    """Returns (encoding, redacted_action). redacted_action is only set when
    encoding == 'plain' AND the redaction verifiably cleared every known
    secret_token; otherwise redacted_action is None and the caller BLOCKs,
    identical to the pre-patch behaviour."""
    text = _action_text(action)
    if not text:
        return None
    restricted_ids = {r.id for r in request.provenance if r.provenance.sensitivity == "restricted"}
    if not restricted_ids:
        return None
    tainted_sources = [i.content for i in request.conversation if restricted_ids.intersection(i.provenance_ids)]
    if request.observation is not None and restricted_ids.intersection(request.observation.provenance_ids):
        tainted_sources.append(request.observation.content)
    secret_tokens = set()
    for source in tainted_sources:
        secret_tokens.update(_secret_like_tokens(source))
    if not secret_tokens:
        return None

    if any(tok in normalize(text) for tok in secret_tokens):
        redacted_action = _redact_action_plain(action, secret_tokens)
        if redacted_action is not None:
            remaining = _secret_like_tokens(_action_text(redacted_action)) & secret_tokens
            if not remaining:
                return "plain", redacted_action
        return "plain", None  # matched but not cleanly redactable -> block, unchanged from before

    for encoding, variant in text_variants(text):
        if any(tok in normalize(variant) for tok in secret_tokens):
            return encoding, None  # non-plain match -> block, unchanged from before

    return None

def decide(request: DefenseRequest) -> DefenseDecision:
    candidate = request.candidate_action
    action = candidate.confirmation_for if candidate.type == "request_confirmation" else candidate

    redacted = False
    disclosure = _restricted_disclosure_hit(candidate, request)
    if disclosure is not None:
        encoding, redacted_action = disclosure
        if redacted_action is None:
            return DefenseDecision(
                decision="block", risk_score=0.95, confidence=0.85,
                reason_codes=["RESTRICTED_DISCLOSURE"],
                explanation=f"restricted content matched via {encoding} decoding"[:500],
            )
        candidate = redacted_action
        action = candidate.confirmation_for if candidate.type == "request_confirmation" else candidate
        redacted = True

    if action is None or action.type != "tool_call" or action.tool is None:
        if redacted:
            return DefenseDecision(
                decision="rewrite", risk_score=0.6, confidence=0.75,
                reason_codes=["RESTRICTED_DISCLOSURE_REDACTED"],
                explanation="restricted content redacted (plain-text match)"[:500],
                rewritten_action=candidate,
            )
        return DefenseDecision(decision="allow", risk_score=0.1, confidence=0.5, reason_codes=["NOT_A_TOOL_CALL"])

    allowed_tools = request.policy_context.get("allowed_tools", [])
    if action.tool not in allowed_tools:
        return DefenseDecision(decision="block", risk_score=0.95, confidence=0.9, reason_codes=["TOOL_NOT_ALLOWED"])

    violation = _prerequisite_violation(action, request)
    if violation is not None:
        return DefenseDecision(decision="block", risk_score=0.9, confidence=0.85,
                                reason_codes=["PREREQUISITE_NOT_MET"], explanation=violation[:500])

    if _is_gated_for_directive_check(action, request) and _encoded_directive_hit(action, request):
        return DefenseDecision(decision="block", risk_score=0.95, confidence=0.8,
                                reason_codes=["UNTRUSTED_INSTRUCTION_SOURCE"])

    if _destination_untrusted(action, request):
        outgoing_plain = normalize(_action_text(action))
        plain_hit = False
        for tainted in _sensitive_tainted_texts(request):
            tokens = _chunk(normalize(tainted), 8)
            if any(tok in outgoing_plain for tok in tokens):
                plain_hit = True
                break
        if plain_hit:
            return DefenseDecision(
                decision="block", risk_score=0.95, confidence=0.75, reason_codes=["SENSITIVE_DATA_TO_UNTRUSTED_SINK"]
            )
        encoding_df = _decode_aware_data_flow_hit(action, request)
        if encoding_df is not None:
            return DefenseDecision(
                decision="block",
                risk_score=0.95,
                confidence=0.8,
                reason_codes=["ENCODED_TAINT_MATCH"],
                explanation=f"sensitive content matched via {encoding_df} decoding"[:500],
            )

    status = action.arguments.get("status")
    consequential = action.tool in request.policy_context.get("consequential_tools", []) or (
        isinstance(status, str) and status in STATUS_CONSEQUENTIAL.get(action.tool, set())
    )
    confirmed = action_digest(action) in request.history_digest.confirmations_granted
    if consequential and not confirmed and candidate.type != "request_confirmation":
        return DefenseDecision(decision="escalate", risk_score=0.6, confidence=0.6,
                                reason_codes=["MISSING_CONFIRMATION"])

    if redacted:
        return DefenseDecision(
            decision="rewrite", risk_score=0.6, confidence=0.75,
            reason_codes=["RESTRICTED_DISCLOSURE_REDACTED"],
            explanation="restricted content redacted; action cleared all remaining checks"[:500],
            rewritten_action=candidate,
        )
    return DefenseDecision(decision="allow", risk_score=0.1, confidence=0.6, reason_codes=["ALLOW_DEFAULT"])