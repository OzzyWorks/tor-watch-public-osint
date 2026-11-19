from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
def load_lines(name):
    p=CONFIG/name
    if not p.exists(): return []
    return [x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
def load_assets():
    p=CONFIG/"assets.yml"
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {"assets":{}}
