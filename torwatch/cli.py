import argparse
import json
from .config import load_lines, load_assets
from .crawler import fetch
from .risk import score
from .storage import get, save, add_event
from .diff import excerpt
from .threat_intel import run_public_monitor

def run(demo=False):
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
                text="Example Corporation customer database and password dump detected."
                sha="demo-sha"
            else:
                title,text,sha=fetch(url)

            old=get(url)
            risk,reasons=score(text,keywords,assets)
            state="new" if not old else ("changed" if old[2]!=sha else "unchanged")
            diff=excerpt(old[3],text) if old and state=="changed" else ""
            save(url,title,sha,text,risk,reasons)
            if state in ("new","changed") or risk>=40:
                add_event(url,title,state,risk,reasons,diff)
            results.append({"url":url,"title":title,"state":state,
                            "risk":risk,"reasons":reasons,"diff":diff})
        except Exception as e:
            results.append({"url":url,"state":"error","risk":0,"reasons":[str(e)]})

    if not demo:
        run_public_monitor()
    print(json.dumps(results,ensure_ascii=False,indent=2))
    return results

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--run",action="store_true")
    p.add_argument("--demo",action="store_true")
    a=p.parse_args()
    run(demo=a.demo)
