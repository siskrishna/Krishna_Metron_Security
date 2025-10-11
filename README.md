# Krishna_Metron Security

Password Strength & Distribution System — CLI tool written in Python.

## Features
- Password strength checker (length, uppercase/lowercase/digit/special).
- Optional HaveIBeenPwned (HIBP) breach check using SHA1 k-anonymity (range API).
- Strong password generator (16–24 chars) with options.
- Send generated password to Slack (webhook or bot token).
- Unit tests (pytest).
- Dockerfile for containerization.

---

## Files
- `main.py` — CLI entrypoint.
- `password_utils.py` — validation and generator.
- `hibp.py` — HIBP range API wrapper (k-anonymity).
- `slack_integration.py` — send to Slack.
- `requirements.txt`, `Dockerfile`, `tests/`.

---

## Setup (local)
1. Create a virtual environment and install:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
