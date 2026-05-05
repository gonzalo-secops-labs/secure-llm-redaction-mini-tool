from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Pattern, Tuple


@dataclass(frozen=True)
class RedactionResult:
    redacted_text: str
    counts: Dict[str, int]
    total_findings: int
    risk_level: str
    secrets_detected: bool


# All pattern names that indicate a secret/credential finding.
_SECRET_TYPES: FrozenSet[str] = frozenset({
    "openai_api_key",
    "aws_access_key_id",
    "jwt",
    "api_key",
    "secret",
    "bearer_token",
})


def _compile_patterns() -> List[Tuple[str, Pattern[str]]]:
    # Note: These patterns intentionally favor "good enough" signal over perfect parsing.
    # The goal is safe redaction assistance, not exact validation.

    email = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

    ipv4 = re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
    )

    # Domain-like (excludes emails; we redact emails first)
    domain = re.compile(
        r"\b(?:(?!-)[A-Z0-9-]{1,63}(?<!-)\.)+(?:[A-Z]{2,63})\b",
        re.IGNORECASE,
    )

    # Conservative hostname:
    # - Prefer machine-like tokens containing a hyphen and/or digits (e.g., ALICE-LAPTOP-01, DC01)
    # - Avoid redacting ordinary words by requiring at least one digit OR a hyphen.
    hostname = re.compile(
        r"\b(?=[A-Z0-9-]{3,63}\b)(?=.*(?:-|\d))[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])\b",
        re.IGNORECASE,
    )

    # Usernames in common alert formats
    username = re.compile(
        r"(?i)(?:\buser(?:name)?\b\s*[:=]\s*|\baccount\b\s*[:=]\s*|\blogin\b\s*[:=]\s*)([A-Z0-9._-]{2,64})"
    )

    windows_path = re.compile(
        r"\b[A-Za-z]:\\(?:[^\\/:*\"<>|\r\n]+\\)*[^\\/:*\"<>|\r\n]+\b"
    )

    linux_path = re.compile(
        r"(?:(?<=\s)|^)\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+(?=\s|$)"
    )

    # Hash patterns: longest first to prevent SHA256 being split into shorter matches.
    sha256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
    sha1 = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
    md5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)

    # --- Secret / credential patterns ---

    # OpenAI-style keys: sk- followed by alphanumeric, hyphens, or underscores (8+ chars).
    # BUG FIX: original pattern used [A-Za-z0-9]{20,} which excluded hyphens,
    # so sk-test-1234567890abcdef would not match.
    openai_key = re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b")

    # AWS access key IDs: AKIA followed by exactly 16 uppercase alphanumeric chars.
    aws_key = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

    # JWT tokens: three base64url-encoded segments separated by dots.
    jwt = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")

    # API key key-value pairs: "api_key=...", "API Key: ...", "apikey=..."
    # BUG FIX: original pattern used api[_-]?key which excluded a space separator,
    # so "API Key: value" would not match.
    api_key_kv = re.compile(
        r"(?i)\bapi[\s_-]?key\s*[:=]\s*[A-Za-z0-9._\-\/+]{8,}"
    )

    # Generic credential key-value pairs: "secret=...", "token: ...", "password=...", "passwd=..."
    secret_kv = re.compile(
        r"(?i)\b(?:secret|token|password|passwd)\s*[:=]\s*[A-Za-z0-9._\-\/+]{8,}"
    )

    # Bearer token: space-separated (no colon/equals needed).
    # BUG FIX: original pattern lumped bearer into generic_secret_kv which required [:=],
    # so "Bearer sk-abc..." (space-separated) would never match.
    bearer = re.compile(
        r"(?i)\bbearer\s+[A-Za-z0-9._\-\/+]{8,}"
    )

    return [
        ("email", email),
        ("ipv4", ipv4),
        ("windows_path", windows_path),
        ("linux_path", linux_path),
        ("sha256", sha256),
        ("sha1", sha1),
        ("md5", md5),
        ("openai_api_key", openai_key),
        ("aws_access_key_id", aws_key),
        ("jwt", jwt),
        ("api_key", api_key_kv),
        ("secret", secret_kv),
        ("bearer_token", bearer),
        ("domain", domain),
        ("hostname", hostname),
        ("username", username),
    ]


_PATTERNS: List[Tuple[str, Pattern[str]]] = _compile_patterns()


def _redaction_tag(label: str) -> str:
    return f"[REDACTED_{label.upper()}]"


def redact_text(text: str) -> RedactionResult:
    counts: Dict[str, int] = {name: 0 for name, _ in _PATTERNS}
    redacted = text

    for name, pattern in _PATTERNS:
        # Special-case username pattern: capture group 1 is the username value.
        if name == "username":
            def _sub_username(match: re.Match[str]) -> str:
                counts[name] += 1
                prefix = match.group(0)
                # Replace only the captured username portion if present.
                captured = match.group(1)
                if captured:
                    return prefix.replace(captured, _redaction_tag(name))
                return _redaction_tag(name)

            redacted = re.sub(pattern, _sub_username, redacted)
            continue

        def _sub(match: re.Match[str]) -> str:
            counts[name] += 1
            return _redaction_tag(name)

        redacted = re.sub(pattern, _sub, redacted)

    # Post-processing: hostname regex is broad; avoid redacting the tags we inserted.
    # If hostname matched inside our tag, it'll already be replaced; this reduces false positives downstream.

    total_findings = sum(counts.values())

    secrets_detected = any(
        counts.get(k, 0) > 0
        for k in _SECRET_TYPES
    )

    if secrets_detected or total_findings > 5:
        risk = "High"
    elif 2 <= total_findings <= 5:
        risk = "Medium"
    else:
        risk = "Low"

    return RedactionResult(
        redacted_text=redacted,
        counts={k: v for k, v in counts.items() if v > 0},
        total_findings=total_findings,
        risk_level=risk,
        secrets_detected=secrets_detected,
    )


def summarize_counts(counts: Dict[str, int]) -> List[Tuple[str, int]]:
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
