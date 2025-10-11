"""
slack_integration.py

Sends a secret message (password) to Slack using incoming webhook or Bot token.
We avoid printing passwords to logs; the function returns boolean status.
"""

import os
import json
import requests
from typing import Optional

def send_to_slack_via_webhook(webhook_url: str, text: str, channel: Optional[str] = None, username: Optional[str] = None) -> bool:
    """
    Send a message to Slack via incoming webhook.
    webhook_url: full webhook URL (keep in env var)
    text: the message (this will contain the password — treat carefully)
    channel: optional override
    username: optional bot name
    Returns True on 200 OK and error False otherwise.

    IMPORTANT: Caller is responsible to not log `text`.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"text": text}
    if channel:
        payload["channel"] = channel
    if username:
        payload["username"] = username

    resp = requests.post(webhook_url, headers=headers, data=json.dumps(payload), timeout=5.0)
    return resp.status_code == 200

def send_to_slack_via_bot_token(token: str, channel_id: str, text: str) -> bool:
    """
    Send a direct message or channel message using Slack Web API chat.postMessage.
    token: Bot OAuth token stored in env var
    channel_id: channel ID or user ID for DM
    NOTE: Caller must not log `text`.
    """
    url = "https://slack.com/api/chat.postMessage"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8"}
    payload = {"channel": channel_id, "text": text}
    resp = requests.post(url, headers=headers, json=payload, timeout=5.0)
    try:
        data = resp.json()
    except Exception:
        return False
    return data.get("ok", False)
