import json
import os
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from redactor import redact_text, summarize_counts


load_dotenv()


APP_ROOT = Path(__file__).resolve().parent
REPO_ROOT = APP_ROOT.parent
SAMPLE_DATA_DIR = REPO_ROOT / "sample-data"


st.set_page_config(
    page_title="Secure LLM Redaction Mini Tool",
    layout="wide",
)

st.title("Secure LLM Redaction Mini Tool")
st.warning(
    "AI output must be reviewed by a human. Never send raw, unredacted alert data to an LLM.",
    icon="⚠️",
)


def _load_sample(filename: str) -> str:
    p = SAMPLE_DATA_DIR / filename
    return p.read_text(encoding="utf-8")


def _normalize_input(raw: str) -> str:
    raw = raw.strip("\ufeff\n\r\t ")
    if not raw:
        return ""

    # If it's JSON, pretty print (helps readability before redaction)
    try:
        parsed = json.loads(raw)
        return json.dumps(parsed, indent=2, sort_keys=True)
    except Exception:
        return raw


with st.sidebar:
    st.header("Sample Data (Safe Demo)")

    if st.button("Load: Suspicious PowerShell", use_container_width=True):
        st.session_state["input_text"] = _load_sample("suspicious-powershell.txt")

    if st.button("Load: Phishing Alert", use_container_width=True):
        st.session_state["input_text"] = _load_sample("phishing-alert.txt")

    if st.button("Load: Login Alert (JSON)", use_container_width=True):
        st.session_state["input_text"] = _load_sample("login-alert.json")

    st.divider()

    st.header("Optional LLM Integration")
    openai_key_present = bool(os.getenv("OPENAI_API_KEY"))
    st.caption(
        "Disabled by default. This MVP does not require external calls. "
        "If you add an LLM feature, it must ONLY use redacted text."
    )
    st.checkbox(
        "OPENAI_API_KEY detected",
        value=openai_key_present,
        disabled=True,
    )


raw_input = st.text_area(
    "Paste SOC alert text or JSON (local only)",
    height=260,
    key="input_text",
    placeholder="Paste alert text or JSON here...",
)

normalized = _normalize_input(raw_input)
result = redact_text(normalized) if normalized else None

col1, col2 = st.columns(2)

with col1:
    st.subheader("Original Input")
    st.code(normalized if normalized else "", language="text")

with col2:
    st.subheader("Redacted Output")
    st.code(result.redacted_text if result else "", language="text")

st.divider()

c1, c2, c3 = st.columns(3)
with c1:
    st.metric("Sensitive Findings", result.total_findings if result else 0)
with c2:
    st.metric("Risk Level", result.risk_level if result else "Low")
with c3:
    st.metric("Secrets Detected", "Yes" if (result and result.secrets_detected) else "No")

st.subheader("Detected Types and Counts")
if result and result.counts:
    rows = [{"type": k, "count": v} for k, v in summarize_counts(result.counts)]
    st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    st.caption("No findings detected.")

st.subheader("Safe Prompt Preview (Redacted Only)")
if result:
    st.text_area(
        "Copy/paste this into your LLM (review first)",
        value=(
            "You are a SOC assistant. Analyze the following redacted alert data. "
            "Do NOT attempt to guess redacted values. Provide recommended triage steps, "
            "hypotheses, and safe next actions.\n\n"
            + result.redacted_text
        ),
        height=220,
    )
else:
    st.caption("Add input to generate a safe prompt preview.")
