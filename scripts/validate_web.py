import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "web" / "index.html"
DATA = ROOT / "web" / "data.json"

source = HTML.read_text(encoding="utf-8")
scripts = re.findall(r"<script>(.*?)</script>", source, flags=re.S)
if not scripts:
    raise SystemExit("Dashboard validation failed: inline JavaScript not found")

with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as handle:
    handle.write("\\n".join(scripts))
    script_path = Path(handle.name)

try:
    result = subprocess.run(["node", "--check", str(script_path)], capture_output=True, text=True)
    if result.returncode:
        raise SystemExit("Dashboard JavaScript syntax error:\\n" + result.stderr)
finally:
    script_path.unlink(missing_ok=True)

if not DATA.exists():
    raise SystemExit("Dashboard data file is missing")
payload = json.loads(DATA.read_text(encoding="utf-8"))
required = ("updated_at", "pages", "events", "site_health", "executive_summary",
            "intelligence_discoveries", "intelligence_incidents")
missing = [key for key in required if key not in payload]
if missing:
    raise SystemExit("Dashboard data is missing required keys: " + ", ".join(missing))
if not isinstance(payload.get("intelligence_discoveries"), list) or not isinstance(payload.get("intelligence_incidents"), list):
    raise SystemExit("Intelligence dashboard collections must be arrays")\nif not payload.get("updated_at"):
    raise SystemExit("Dashboard data timestamp is empty")
if not payload.get("pages") or not payload.get("site_health"):
    raise SystemExit("Dashboard export is unexpectedly empty; refusing to publish")
if not payload.get("executive_summary", {}).get("headline"):
    raise SystemExit("Executive summary headline is missing")

print(
    "Dashboard validation passed: JavaScript syntax OK; "
    f"pages={len(payload['pages'])}, site_health={len(payload['site_health'])}, "
    f"events={len(payload['events'])}"
)
