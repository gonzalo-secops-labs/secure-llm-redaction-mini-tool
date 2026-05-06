# Secure LLM Redaction Mini Tool

A lightweight Streamlit app that helps SOC teams **redact sensitive indicators** from alert text/JSON before sharing it with an LLM.

This is a **demo** project.

## Problem

SOC alerts often contain sensitive data (PII, infrastructure details, credentials/tokens, internal hostnames, file paths). Copy/pasting raw alerts into an LLM can create data exposure risk.

## Solution

This tool:

- Runs locally (no database, no authentication)
- Provides safe demo sample alerts
- Detects and redacts common sensitive fields
- Produces a **Safe Prompt Preview** that uses **redacted data only**

**Important:** AI output must be reviewed by a human. This tool is not a substitute for your organization’s policies.

## Workflow

- Paste alert text or JSON
- (Optional) Load a safe demo sample
- Review detected sensitive types and counts
- Copy the **Safe Prompt Preview** (redacted only) into your LLM workflow

## Features

- Paste area for SOC alert text/JSON
- Sample data loaders (safe, fabricated)
- Redaction engine detects and redacts:
  - Email addresses
  - IPv4 addresses
  - Domains
  - Hostnames
  - Usernames
  - Windows file paths
  - Linux file paths
  - MD5/SHA1/SHA256 hashes
  - Possible API keys / secrets / tokens (high-signal patterns)
- Side-by-side original vs redacted view
- Detected types + counts
- Simple risk level:
  - Low: 0-1 findings
  - Medium: 2-5 findings
  - High: >5 findings OR any secret/token patterns detected
- Safe Prompt Preview (redacted only)

## Setup

### Prerequisites

- Python 3.10+

### Install

From the repo root:

```bash
python -m venv .venv
```

Activate your venv:

- Windows (PowerShell)

```bash
.venv\\Scripts\\Activate.ps1
```

Install dependencies:

```bash
pip install -r src/requirements.txt
```

Run the app:

```bash
streamlit run src/app.py
```

## Security Notes

- This repo includes **safe demo data only** in `sample-data/`.
- Do not commit any real alert data.
- `.env` is ignored by `.gitignore`. Use `.env.example` as a template.
- No external calls are required for the MVP.
- Any future LLM integration must:
  - Be optional
  - Be disabled unless `OPENAI_API_KEY` exists in the environment
  - **Never send raw/unredacted input**

## Limitations

- Redaction uses regex heuristics; it will have false positives/negatives.
- Hostname/domain detection is best-effort (alerts vary widely).
- This is not a DLP solution and does not enforce policy.

## Future Improvements

- Custom redaction rules per organization
- Allowlist / preserve list (e.g., keep public IPs)
- Better structured JSON field-level redaction
- Export redaction report (JSON)
- Optional LLM analysis of **redacted-only** content (explicitly gated by env var)
