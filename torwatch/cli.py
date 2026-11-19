import argparse,json
from .config import load_lines,load_assets
from .crawler import fetch
from .risk import score
from .storage import get,save
from .diff import excerpt
from .notifier import notify
def run(demo=False):
    keywords=load_lines("keywords.txt"); assets=load_assets().get("assets",{}); urls=load_lines("watchlist.txt"); results=[]
    if demo: urls=["demo://example"]
    for url in urls:
        try:
            if demo: title,text,sha="Demo Leak Notice","Example Corporation customer database and password dump detected.","demo-sha"
            else: title,text,sha=fetch(url)
            old=get(url); risk,reasons=score(text,keywords,assets); state="new" if not old else ("changed" if old[2]!=sha else "unchanged"); diff=excerpt(old[3],text) if old and state=="changed" else ""
            save(url,title,sha,text,risk,reasons); item={"url":url,"title":title,"state":state,"risk":risk,"reasons":reasons,"diff":diff}; results.append(item)
            if state in ("new","changed") or risk>=40:
                level="CRITICAL" if risk>=70 else ("HIGH" if risk>=40 else "INFO")
                msg=f"*Tor Watch {level}*\n{state.upper()} | risk={risk}\n{title}\n{url}"
                if reasons: msg += "\nReasons: "+", ".join(reasons[:8])
                if diff: msg += "\nDiff: "+diff[:1200]
                notify(msg)
        except Exception as e: results.append({"url":url,"state":"error","risk":0,"reasons":[str(e)]})
    print(json.dumps(results,ensure_ascii=False,indent=2)); return results
if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--run",action="store_true"); p.add_argument("--demo",action="store_true"); a=p.parse_args(); run(demo=a.demo)
