import argparse
import hashlib
import json
from .config import load_lines, load_assets
from .crawler import fetch
from .risk import canonical_company_key, score
from .storage import (
    get, save, add_event, enqueue_notification, pending_notifications,
    mark_notification_sent, mark_notification_failed, record_site_check,
)
from .notifier import notify
from .diff import excerpt
from .threat_intel import run_public_monitor

def _level(risk):
    if risk >= 85: return "CRITICAL"
    if risk >= 70: return "HIGH"
    if risk >= 50: return "MEDIUM"
    return "LOW"

def _classify_fetch_error(exc):
    name=type(exc).__name__.lower()
    message=str(exc).lower()
    if "timeout" in name or "timed out" in message:
        return "timeout"
    if "0x04" in message or "host unreachable" in message:
        return "onion_unreachable"
    if "0x05" in message or "connection refused" in message:
        return "connection_refused"
    if "0x01" in message or "general socks server failure" in message:
        return "tor_socks_error"
    if "http redirect" in message or "redirect chain" in message:
        return "http_redirect"
    if "html" in message and ("返しません" in message or "not return" in message):
        return "non_html_response"
    if "http" in name:
        return "http_error"
    if "connection" in name:
        return "connection_error"
    return "fetch_error"

def _has_relevant_change(old,risk,reasons):
    """Ignore homepage churn unless a watched company is newly implicated or risk rises.

    Leak-site homepages can contain many historical victim cards. A new unrelated
    card must not trigger an alert for companies already listed elsewhere.
    """
    if old is None:
        return True
    old_risk=int(old[4] or 0)
    old_companies={
        canonical_company_key(part.split(":",1)[1])
        for part in str(old[5] or "").split(" | ")
        if part.startswith("company:")
    }
    new_companies={
        canonical_company_key(reason.split(":",1)[1])
        for reason in reasons or []
        if reason.startswith("company:")
    }
    return risk>old_risk or bool(new_companies-old_companies)

def _reason_text(reasons):
    labels=[]
    for reason in reasons:
        if reason.startswith("company:"):
            labels.append("対象企業: "+reason.split(":",1)[1])
        elif reason.startswith("nearby_breach:"):
            labels.append("企業名の近くで検出した漏洩・攻撃関連語: "+reason.split(":",1)[1])
        elif reason.startswith("nearby_data:"):
            labels.append("企業名の近くで検出した情報種別: "+reason.split(":",1)[1])
        elif reason.startswith("nearby_claim:"):
            labels.append("企業名の近くで検出した掲載情報: "+reason.split(":",1)[1])
        elif reason.startswith("global_keyword:"):
            labels.append("ページ全体の参考キーワード: "+reason.split(":",1)[1])
        elif reason.startswith("basis:"):
            labels.append("判定根拠: "+reason.split(":",1)[1])
    return labels or ["判定根拠の詳細なし"]

def _alert_message(url,title,state,risk,reasons):
    level=_level(risk)
    companies=[r.split(":",1)[1] for r in reasons if r.startswith("company:")]
    company_text="、".join(dict.fromkeys(companies)) if companies else "監視対象企業との一致なし"
    event_text={"new":"新規ページ検出","changed":"ページ内容の更新","unchanged":"継続中の高リスク検知（初回通知）","reclassified":"リスク判定の見直し（機械判定）"}.get(state,state)
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

            if not demo:
                record_site_check(url,"ok",title=title)

            old=get(url)
            risk,reasons=score(text,keywords,assets)
            state="new" if not old else ("changed" if old[2]!=sha else "unchanged")
            old_risk=old[4] if old else 0
            relevant_change=_has_relevant_change(old,risk,reasons)
            diff=excerpt(old[3],text) if old and state=="changed" else ""
            level=_level(risk)
            previous_level=_level(old_risk) if old else "NONE"

            # Notify only meaningful new/changed findings. MEDIUM is included for
            # newly discovered pages; existing pages need HIGH+ or escalation.
            risk_revised = old is not None and old_risk>=85 and 50<=risk<85
            should_notify=(
                risk_revised or
                (old is None and risk>=50) or
                (state=="changed" and relevant_change and risk>=70) or
                (old is not None and old_risk<70 and risk>=70 and relevant_change) or
                # Notify when a previously low-risk page gains a watched company or risk evidence.
                (old is not None and old_risk<55 and risk>=55 and relevant_change) or
                # Backfill only when the current scan adds a watched company or raises risk.
                (old is not None and state=="unchanged" and risk>=70 and relevant_change)
            )
            # Keep history meaningful: unchanged scans are observations, not new events.
            # Record content changes and risk reclassifications only.
            if state=="new":
                add_event(url,title,state,risk,reasons,diff)
            elif state=="changed" and relevant_change:
                add_event(url,title,state,risk,reasons,diff)
            elif old is not None and _level(old_risk) != level:
                add_event(url,title,"reclassified",risk,reasons,
                          f"Risk level changed: {_level(old_risk)} -> {level}")
            elif state=="changed":
                print("TorWatch: page changed without a new watched-company match or risk increase; event suppressed")
            if should_notify and not demo:
                # Dedupe by page content + risk band, independent of event state.
                # This sends pre-existing HIGH/CRITICAL findings once after deployment.
                matched_companies=sorted(
                    r.split(":",1)[1] for r in reasons if r.startswith("company:")
                )
                # Identical mirrors with identical content share one notification.
                event_key=hashlib.sha256(
                    f"{sha}|{level}|{'|'.join(matched_companies)}".encode("utf-8")
                ).hexdigest()
                alert_state = "reclassified" if risk_revised else state
                queued=enqueue_notification(event_key,_alert_message(url,title,alert_state,risk,reasons))
                if queued:
                    print(f"Slack: queued {level} alert for {url}")
                else:
                    print(f"Slack: duplicate suppressed for {url} ({level})")

            save(url,title,sha,text,risk,reasons)
            results.append({
                "url":url,"title":title,"state":state,"risk":risk,
                "risk_level":level,"previous_risk_level":previous_level,
                "companies":[r.split(":",1)[1] for r in reasons if r.startswith("company:")],
                "reasons":reasons,"diff":diff,"slack_queued":bool(should_notify and not demo)
            })
        except Exception as e:
            error_type=_classify_fetch_error(e)
            if not demo:
                record_site_check(url,"error",error_type=error_type,error=str(e))
            results.append({
                "url":url,"state":"error","risk":None,
                "risk_level":"NOT_SCANNED","companies":[],
                "reasons":[f"取得エラー（{error_type}）: {str(e)[:220]}"],
                "scanned":False,"slack_queued":False
            })

    if not demo:
        run_public_monitor()
        _send_queued_notifications()
    print(json.dumps(results,ensure_ascii=False,indent=2))
    return results

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--run",action="store_true")
    p.add_argument("--demo",action="store_true")
    p.add_argument("--test-slack",action="store_true",help="Send a one-time Slack webhook test")
    a=p.parse_args()
    run(demo=a.demo,test_slack=a.test_slack)
