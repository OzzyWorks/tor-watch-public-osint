"""Context-aware risk scoring for public leak-site pages.

A company-name match alone is never enough for HIGH/CRITICAL.
The strongest levels require breach language and sensitive-data indicators
near the matched company name in the page text.
"""
import re

BREACH_TERMS = (
    "ransomware", "leak", "dump", "stealer", "exfiltrat", "data breach",
    "data leak", "stolen", "extortion", "情報漏えい", "情報漏洩",
    "情報流出", "データ流出", "窃取", "ランサムウェア",
)
CLAIM_TERMS = ("data size", "downloaded data", "data volume", "stolen data size")
DATA_TERMS = (
    "database", "customer data", "client data", "employee data", "personal data",
    "credit card", "password", "credentials", "api key", "secret",
    "顧客情報", "従業員情報", "個人情報", "クレジットカード", "データベース",
)

def canonical_company_key(value):
    """Collapse English legal-form suffixes so aliases map to one organisation."""
    raw=str(value or "").strip().casefold()
    if not re.fullmatch(r"[a-z0-9 .,&'()_-]+",raw):
        return raw
    tokens=re.findall(r"[a-z0-9]+",raw)
    legal_suffixes={"inc","incorporated","corp","corporation","co","company","ltd","limited"}
    while tokens and tokens[-1] in legal_suffixes:
        tokens.pop()
    return " ".join(tokens)


def _occurrences(text, value):
    pattern = re.escape(str(value).strip())
    if re.fullmatch(r"[A-Za-z0-9 .,&'()_-]+", str(value).strip()):
        pattern = r"(?<![A-Za-z0-9])" + pattern + r"(?![A-Za-z0-9])"
    return [m.start() for m in re.finditer(pattern, text, re.IGNORECASE)]

def _terms_in(text, terms):
    low = text.casefold()
    return [term for term in terms if term.casefold() in low]

def score(text, keywords, assets):
    """Return (0-100 risk, machine-readable reasons)."""
    source = str(text or "")
    companies = []
    evidence_by_company = []
    all_assets = assets or {}
    name_labels = {}

    # Match registered names and domains, then inspect only the nearby context.
    for category in ("names", "domains", "emails", "services"):
        for raw in all_assets.get(category, []) or []:
            value = str(raw).strip()
            if len(value) < 4:
                continue
            # The crawler joins the landing page and each detail page with an
            # explicit boundary. Never let evidence on one page raise the score
            # for a company mentioned on a different page.
            segments = re.split(r"\n\s*\[TORWATCH_PAGE_BOUNDARY\]\s*\n", source)
            positions = [
                (segment, pos)
                for segment in segments
                for pos in _occurrences(segment, value)
            ]
            if not positions:
                continue
            label = value
            if category == "names":
                key = canonical_company_key(value)
                label = name_labels.setdefault(key, value)
            if label not in companies:
                companies.append(label)
            for segment, pos in positions:
                context = segment[max(0, pos - 650): min(len(segment), pos + len(value) + 650)]
                breach = _terms_in(context, BREACH_TERMS)
                claims = _terms_in(context, CLAIM_TERMS)
                sensitive = _terms_in(context, DATA_TERMS)
                evidence_by_company.append((label, breach, claims, sensitive))

    # Keep the risk score attached only to the company whose own nearby
    # evidence produced that score. A high-risk mention of Company A must not
    # make every other company name on the same page look equally affected.
    per_company = {}
    for company, breach, claims, sensitive in evidence_by_company:
        if breach and len(set(sensitive)) >= 2:
            score_value = 90
        elif breach and sensitive:
            score_value = 75
        elif claims and breach:
            score_value = 70
        elif claims:
            score_value = 55
        elif breach or len(set(sensitive)) >= 2:
            score_value = 55
        elif sensitive:
            score_value = 35
        else:
            score_value = 20
        item = per_company.setdefault(company, {
            "score": 0, "breach": [], "claims": [], "sensitive": []
        })
        if score_value > item["score"]:
            item["score"] = score_value
            item["breach"] = breach
            item["claims"] = claims
            item["sensitive"] = sensitive

    strongest = max((item["score"] for item in per_company.values()), default=0)
    companies = [name for name, item in per_company.items()
                 if item["score"] == strongest]
    best = next((item for item in per_company.values()
                 if item["score"] == strongest), {})
    best_breach = best.get("breach", [])
    best_claims = best.get("claims", [])
    best_sensitive = best.get("sensitive", [])
    reasons = ["company:" + name for name in companies]

    if companies:
        if best_breach:
            reasons.append("nearby_breach:" + ", ".join(best_breach))
        if best_claims:
            reasons.append("nearby_claim:" + ", ".join(best_claims))
        if best_sensitive:
            reasons.append("nearby_data:" + ", ".join(best_sensitive))
        if strongest >= 90:
            reasons.append("basis:企業名の近くに漏洩関連語と複数の機微情報種別を検出")
        elif strongest >= 75:
            reasons.append("basis:企業名の近くに漏洩関連語と機微情報種別を検出")
        elif strongest >= 70:
            reasons.append("basis:企業名の近くに漏洩関連語とデータ量表示を検出。流出の真偽は未確認")
        elif strongest >= 55:
            reasons.append("basis:企業名の近くにデータ量などの掲載情報、漏洩関連語または複数の情報種別を検出。流出の真偽は未確認")
        elif strongest >= 35:
            reasons.append("basis:企業名の近くに情報種別を検出。漏洩主張は未確認")
        else:
            reasons.append("basis:企業名の一致のみ。被害を示す具体的な根拠は未検出")
        return strongest, reasons

    # No monitored company matched: page-wide keywords are context only and
    # cannot independently create a HIGH or CRITICAL company alert.
    low = source.casefold()
    matched = []
    for keyword in keywords or []:
        term = str(keyword).strip()
        if term and term.casefold() in low and term not in matched:
            matched.append(term)
    if matched:
        reasons.append("global_keyword:" + ", ".join(matched[:8]))
    reasons.append("basis:監視対象企業との一致なし。参考情報")
    return min(30, len(matched) * 3), reasons


def assess_evidence(reasons, source_type="leak_site"):
    """Describe evidence strength separately from risk; never imply confirmation."""
    parts = [str(x) for x in (reasons or [])]
    has_company = any(x.startswith(("company:", "company_context:", "company_match:")) for x in parts)
    has_breach = any(x.startswith(("nearby_breach:", "incident_term:")) for x in parts)
    has_data = any(x.startswith("nearby_data:") for x in parts)
    has_claim = any(x.startswith("nearby_claim:") for x in parts)
    if not has_company:
        strength, label, status = 0, "対象企業との一致なし", "監視対象企業との関連未確認"
    elif has_breach and has_data:
        strength, label, status = 75, "複数の根拠語が近接", "漏洩・侵害の掲載主張あり（真偽未確認）"
    elif has_breach:
        strength, label, status = 60, "漏洩・侵害関連語あり", "漏洩・侵害の掲載主張あり（真偽未確認）"
    elif has_claim:
        strength, label, status = 40, "データ量等の掲載表現のみ", "掲載情報あり・漏洩主張は未確認"
    elif has_data:
        strength, label, status = 35, "情報種別の記載あり", "情報種別の記載あり・被害との関連未確認"
    else:
        strength, label, status = 15, "企業名の一致のみ", "企業名の一致のみ・被害根拠なし"
    if source_type == "public_report" and has_company and has_breach:
        status = "公開報道・情報源の記載あり（企業公式確認は未判定）"
    return {
        "evidence_strength": strength,
        "evidence_label": label,
        "evidence_status": status,
        "officially_confirmed": False,
    }
