import os,requests
def notify(message):
    url=os.getenv("SLACK_WEBHOOK_URL")
    if not url:return False
    r=requests.post(url,json={"text":message},timeout=15); r.raise_for_status(); return True
