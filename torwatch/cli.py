import argparse
import hashlib
import json
from .config import load_lines, load_assets
from .crawler import fetch
from .risk import score
from .storage import (
    get, save, add_event, enqueue_notification, pending_notifications,
    mark_notification_sent, mark_notification_failed,
)
from .notifier import notify
from .diff import excerpt
from .threat_intel import run_public_monitor

def _level(risk):
    if risk >= 85: return "CRITICAL"
    if risk >= 70: return "HIGH"
    if risk >= 50: return "MEDIUM"
    return "LOW"

def _reason_text(reasons):
    labels=[]
    for reason in reasons:
        if reason.startswith("company:"):
            labels.append("対象企業: "+reason.split(":",1)[1])
        elif reason.startswith("nearby_breach:"):
            labels.append("企業名の近くで検出した漏洩・攻撃関連語: "+reason.split(":",1)[1])
        elif reason.startswith("nearby_data:"):
            labels.append("企業名の近くで検出した情報種別: "+reason.split(":",1)[1])
        elif reason.startswith("global_keyword:"):
            labels.append("ページ全体の参考キーワード: "+reason.split(":",1)[1])
        elif reason.startswith("basis:"):
            labels.append("判定根拠: "+reason.split(":",1)[1])
    return labels or ["判定根拠の詳細なし"]

def _alert_message(url,title,state,risk,reasons):
    level=_level(risk)
    companies=[r.split(":",1)[1] for r in reasons if r.startswith("company:")]
    company_text="、".join(dict.fromkeys(companies)) if companies else "監視対象企業との一致なし"
    event_text={"new":"新規ページ検出","changed":"ページ内容の更新","unchanged":"リスク判定の変化"}.get(state,state)
    lines=[
        f"🛡️ *Tor Watch / {level} ({risk}/100)*",
        f"*対象企業:* {company_text}",
        f"*検知内容:* {event_text}",
        f"*ページ:* {title or '(タイトルなし)'}",
        "*判定理由:*",
    ]
    lines += ["• "+x for x in _reason_text(reasons)]
    lines += [
        "*確認状況:* 公開リークサイト上の記載を検出。実際の流出・真偽は未確認。",
        f"*検知URL:* {url}",
    ]
    return "\n".join(lines)

def _send_queued_notifications():
    queue=pending_notifications()
    if not queue:
        print("Slack: 送信待ち通知はありません")
        return
    sent=0
    failed=0
    for item in queue:
        try:
            notify(item["message"])
            mark_notification_sent(item["id"])
            sent+=1
        except Exception as exc:
            mark_notification_failed(item["id"],exc)
            failed+=1
            print(f"Slack notification failed (id={item['id']}): {str(exc)[:250]}")
    print(f"Slack notifications: sent={sent}, failed={failed}, remaining_pending={failed}")

def run(demo=False, test_slack=False):
    if test_slack:
        notify("🛡️ Tor Watch Slack接続テスト：Webhookへの送信に成功しました。")
        return [{"slack_test":"sent"}]
    keywords=load_lines("keywords.txt")
    assets=load_assets().get("assets",{})
    urls=load_lines("watchlist.txt")
    results=[]

    if demo:
        urls=["demo://example"]

    for url in urls:
        try:
            if demo:
                title="Demo Leak Notice"
                text="Example Corporation ransomware leak: customer database and employee personal data dump."
                sha="demo-sha"
            else:
                title,text,sha=fetch(url)

            old=get(url)
            risk,reasons=score(text,keywords,assets)
            state="new" if not old else ("changed" if old[2]!=sha else "unchanged")
            old_risk=old[4] if old else 0
            diff=excerpt(old[3],text) if old and state=="changed" else ""
            level=_level(risk)
            previous_level=_level(old_risk) if old else "NONE"

            # Notify only meaningful new/changed findings. MEDIUM is included for
            # newly discovered pages; existing pages need HIGH+ or escalation.
            should_notify=(
                (old is None and risk>=50) or
                (state=="changed" and risk>=70) or
                (old is not None and old_risk<70 and risk>=70)
            )
            if state in ("new","changed") or risk>=50:
                add_event(url,title,state,risk,reasons,diff)
            if should_notify and not demo:
                event_key=hashlib.sha256(
                    f"{url}|{sha}|{level}|{state}".encode("utf-8")
                ).hexdigest()
                enqueue_notification(event_key,_alert_message(url,title,state,risk,reasons))

            save(url,title,sha,text,risk,reasons)
            results.append({
                "url":url,"title":title,"state":state,"risk":risk,
                "risk_level":level,"previous_risk_level":previous_level,
                "companies":[r.split(":",1)[1] for r in reasons if r.startswith("company:")],
                "reasons":reasons,"diff":diff,"slack_queued":bool(should_notify and not demo)
            })
        except Exception as e:
            results.append({"url":url,"state":"error","risk":0,"reasons":[str(e)]})

    if not demo:
        run_public_monitor()
        _send_queued_notifications()
    print(json.dumps(results,ensure_ascii=False,indent=2))
    return results

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--run",action="store_true")
    p.add_argument("--demo",action="store_true")\n    p.add_argument("--test-slack",action="store_true",help="Send a one-time Slack webhook test")
    a=p.parse_args()
    run(demo=a.demo,test_slack=a.test_slack)
