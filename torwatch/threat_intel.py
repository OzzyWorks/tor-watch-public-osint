"""Monitor configured public RSS/Atom feeds for company-specific incident reports.
Only public article metadata is collected; linked leak files are never downloaded.
"""
import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from bs4 import BeautifulSoup

from .config import CONFIG, load_assets
from .risk import canonical_company_key
from .storage import add_threat_item, list_threat_items, enqueue_notification

UA = "TorWatch-Public-OSINT/0.4 (+public defensive monitoring)"
MAX_BYTES = 2_000_000
THREAT_STRONG = (
    "ransomware", "ランサムウェア", "情報漏えい", "情報漏洩", "個人情報流出",
    "データ流出", "情報流出", "窃取", "不正アクセス", "侵害", "data breach",
    "data leak", "stolen data", "exfiltrat", "extortion", "customer data exposed",
)
THREAT_MEDIUM = ("サイバー攻撃", "サイバーインシデント", "cyberattack", "cyber attack", "security incident")

def _local(tag):
    return tag.rsplit("}", 1)[-1].lower()

def _text(node, names):
    for child in list(node):
        if _local(child.tag) in names:
            value=" ".join(child.itertext()).strip()
            if value:
                return value
    return ""

def _parse_feed(payload):
    root=ET.fromstring(payload)
    entries=[n for n in root.iter() if _local(n.tag) in ("item","entry")]
    out=[]
    for node in entries[:60]:
        title=_text(node,{"title"})
        summary=_text(node,{"description","summary","content","encoded"})
        link=""
        for child in list(node):
            if _local(child.tag)=="link":
                link=child.attrib.get("href","") or (child.text or "").strip()
                if link: break
        guid=_text(node,{"guid","id"})
        published=_text(node,{"pubdate","published","updated","date"})
        summary=BeautifulSoup(summary,"html.parser").get_text(" ",strip=True)
        if title or summary:
            out.append({"title":title,"summary":summary,"url":link or guid,
                        "guid":guid,"published":published})
    return out

def _matches(text, assets):
    found=[]
    seen_name_keys=set()
    for category in ("names","domains","emails","services"):
        for raw in (assets or {}).get(category,[]) or []:
            value=str(raw).strip()
            if not value or len(value)<4:
                continue
            if category=="domains":
                pattern=r"(?<![A-Za-z0-9.-])"+re.escape(value.lower())+r"(?![A-Za-z0-9.-])"
                hit=re.search(pattern,text.lower()) is not None
            elif re.fullmatch(r"[A-Za-z0-9 .,&'()_-]+",value):
                hit=re.search(r"(?<![A-Za-z0-9])"+re.escape(value.lower())+r"(?![A-Za-z0-9])",text.lower()) is not None
            else:
                hit=value.casefold() in text.casefold()
            if hit:
                if category=="names":
                    key=canonical_company_key(value)
                    if key not in seen_name_keys:
                        found.append(value)
                        seen_name_keys.add(key)
                elif value not in found:
                    found.append(value)
    return found

def _risk(text):
    low=text.casefold()
    strong=[term for term in THREAT_STRONG if term.casefold() in low]
    medium=[term for term in THREAT_MEDIUM if term.casefold() in low]
    if strong:
        return 75,["incident_term:"+x for x in strong[:4]]
    if medium:
        return 55,["incident_term:"+x for x in medium[:3]]
    return 0,[]

def _risk_near_matches(text, matches, radius=450):
    """Attribute incident terms to the nearest matched organisation, not every
    organisation that happens to fall inside a broad article window.
    """
    folded = str(text or "").casefold()
    organisations = []
    for match in matches or []:
        needle = str(match).casefold()
        if not needle:
            continue
        start = 0
        while True:
            pos = folded.find(needle, start)
            if pos < 0:
                break
            organisations.append((pos, pos + len(needle), str(match)))
            start = pos + max(1, len(needle))
    if not organisations:
        return 0, ["basis:企業名と近接するインシデント根拠なし"]

    strong_hits = []
    medium_hits = []
    for term in THREAT_STRONG:
        needle = term.casefold()
        start = 0
        while True:
            pos = folded.find(needle, start)
            if pos < 0:
                break
            strong_hits.append((pos, pos + len(needle), term))
            start = pos + max(1, len(needle))
    for term in THREAT_MEDIUM:
        needle = term.casefold()
        start = 0
        while True:
            pos = folded.find(needle, start)
            if pos < 0:
                break
            medium_hits.append((pos, pos + len(needle), term))
            start = pos + max(1, len(needle))

    attributed = {}
    for hit_start, hit_end, term in strong_hits + medium_hits:
        hit_mid = (hit_start + hit_end) // 2
        nearest = min(
            organisations,
            key=lambda item: min(abs(hit_mid - item[0]), abs(hit_mid - item[1]))
        )
        distance = min(abs(hit_mid - nearest[0]), abs(hit_mid - nearest[1]))
        if distance > radius:
            continue
        name = nearest[2]
        bucket = attributed.setdefault(name, {"strong": [], "medium": []})
        bucket["strong" if (hit_start, hit_end, term) in strong_hits else "medium"].append(term)

    if not attributed:
        return 0, ["basis:企業名と近接するインシデント根拠なし"]

    scored = []
    for name, terms in attributed.items():
        if terms["strong"]:
            risk = 75
            reasons = ["incident_term:" + x for x in dict.fromkeys(terms["strong"][:4])]
        elif terms["medium"]:
            risk = 55
            reasons = ["incident_term:" + x for x in dict.fromkeys(terms["medium"][:3])]
        else:
            continue
        scored.append((risk, name, reasons))

    if not scored:
        return 0, ["basis:企業名と近接するインシデント根拠なし"]
    best_risk = max(item[0] for item in scored)
    best = [item for item in scored if item[0] == best_risk]
    return best_risk, (
        ["company_context:" + item[1] for item in best]
        + list(dict.fromkeys(reason for item in best for reason in item[2]))
    )

def run_public_monitor():
    config_path=CONFIG/"sources.yml"
    if not config_path.exists():
        print("Public OSINT: config/sources.yml not found; skipped")
        return []
    cfg=yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    assets=load_assets().get("assets",{})
    session=requests.Session()
    session.headers.update({"User-Agent":UA,"Accept":"application/rss+xml, application/atom+xml, application/xml, text/xml"})
    results=[]
    for source in cfg.get("sources",[]) or []:
        if not source.get("enabled",True):
            continue
        feed_url=str(source.get("url","")).strip()
        if urlparse(feed_url).scheme!="https":
            results.append({"source":source.get("name","?"),"error":"HTTPS以外のfeedは許可しません"})
            continue
        try:
            response=session.get(feed_url,timeout=20,stream=True)
            response.raise_for_status()
            chunks=[]
            size=0
            for chunk in response.iter_content(65536):
                size+=len(chunk)
                if size>MAX_BYTES:
                    raise ValueError("feed exceeds 2 MB limit")
                chunks.append(chunk)
            entries=_parse_feed(b"".join(chunks))
            new_count=0
            for entry in entries:
                body=" ".join((entry["title"],entry["summary"]))
                matches=_matches(body,assets)
                if not matches:
                    continue
                risk,reasons=_risk_near_matches(body,matches)
                if risk<45:
                    continue
                # Only attribute the alert to organisations whose own nearby
                # context contains incident language; other names in the same
                # article are not automatically affected companies.
                contextual_matches=[
                    reason.split(":",1)[1] for reason in reasons
                    if reason.startswith("company_context:")
                ]
                if contextual_matches:
                    matches=contextual_matches
                url=entry["url"] or feed_url
                identity=entry["guid"] or url or (entry["title"]+entry["published"])
                item_id=hashlib.sha256((source.get("id","")+"|"+identity).encode("utf-8")).hexdigest()
                reasons += ["company_match:"+x for x in matches]
                item={
                    "id":item_id,"source":source.get("name","RSS"),
                    "title":entry["title"] or "(タイトルなし)","url":url,
                    "published":entry["published"],"matched_assets":matches,
                    "risk":risk,"reasons":reasons,
                    "status":"公開情報・報道ベース（企業公式確認は未判定）"
                }
                if add_threat_item(item):
                    new_count+=1
                    if risk>=55:
                        message=(
                            f"🛡️ *Tor Watch 企業関連アラート*\n"
                            f"*対象:* {', '.join(matches)}\n"
                            f"*重要度:* {'HIGH' if risk>=70 else 'MEDIUM'} ({risk}/100)\n"
                            f"*記事:* {item['title']}\n"
                            f"*情報源:* {item['source']}\n"
                            f"*検出語:* {', '.join(x.split(':',1)[1] for x in reasons if x.startswith('incident_term:'))}\n"
                            f"*確認状況:* {item['status']}\n{url}"
                        )
                        if enqueue_notification(item_id,message):
                            print("Slack RSS alert queued:", item["title"][:120])
            results.append({"source":source.get("name","?"),"items":len(entries),"new_alerts":new_count})
        except Exception as exc:
            results.append({"source":source.get("name","?"),"error":str(exc)[:300]})
    print("Public OSINT:",results)
    return results

def recent_public_alerts(limit=100):
    return list_threat_items(limit)
