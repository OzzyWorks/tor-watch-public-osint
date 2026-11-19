"""Slack incoming-webhook delivery."""
import os
import requests

def notify(message):
    url=os.getenv("SLACK_WEBHOOK_URL","").strip()
    if not url:
        raise RuntimeError("SLACK_WEBHOOK_URL is not configured")
    if not url.startswith("https://hooks.slack.com/"):
        raise RuntimeError("SLACK_WEBHOOK_URL does not look like a Slack incoming webhook")
    response=requests.post(url,json={"text":message},timeout=20)
    response.raise_for_status()
    if response.text.strip().lower() != "ok":
        raise RuntimeError("Slack webhook returned an unexpected response")
    return True
