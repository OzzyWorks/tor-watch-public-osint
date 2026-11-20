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
            positions = _occurrences(source, value)
            if not positions:
                continue
            label = value
            if category == "names":
                key = canonical_company_key(value)
                label = name_labels.setdefault(key, value)
            if label not in companies:
                companies.append(label)
            for pos in positions:
                context = source[max(0, pos - 650): min(len(source), pos + len(value) + 650)]
                breach = _terms_in(context, BREACH_TERMS)
                claims = _terms_in(context, CLAIM_TERMS)
                sensitive = _terms_in(context, DATA_TERMS)
                evidence_by_company.append((label, breach, claims, sensitive))

    reasons = ["company:" + name for name in companies]
    strongest = 0
    best_breach = []
    best_claims = []
    best_sensitive = []

    for company, breach, claims, sensitive in evidence_by_company:
        # Score each company independently; don't combine unrelated page sections.
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
        if score_value > strongest:
            strongest = score_value
            best_breach = breach
            best_claims = claims
            best_sensitive = sensitive

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
