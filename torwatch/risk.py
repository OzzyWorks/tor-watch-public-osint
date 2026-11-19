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
DATA_TERMS = (
    "database", "customer", "client", "employee", "personal data",
    "credit card", "password", "credential", "api key", "secret",
    "顧客", "従業員", "個人情報", "クレジットカード", "データベース",
)

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
            if label not in companies:
                companies.append(label)
            for pos in positions:
                context = source[max(0, pos - 220): min(len(source), pos + len(value) + 220)]
                breach = _terms_in(context, BREACH_TERMS)
                sensitive = _terms_in(context, DATA_TERMS)
                evidence_by_company.append((label, breach, sensitive))

    reasons = ["company:" + name for name in companies]
    strongest = 0
    best_breach = []
    best_sensitive = []

    for company, breach, sensitive in evidence_by_company:
        # Score each company independently; don't combine unrelated page sections.
        if breach and len(set(sensitive)) >= 2:
            score_value = 90
        elif breach and sensitive:
            score_value = 75
        elif breach or len(set(sensitive)) >= 2:
            score_value = 55
        elif sensitive:
            score_value = 35
        else:
            score_value = 20
        if score_value > strongest:
            strongest = score_value
            best_breach = breach
            best_sensitive = sensitive

    if companies:
        if best_breach:
            reasons.append("nearby_breach:" + ", ".join(best_breach))
        if best_sensitive:
            reasons.append("nearby_data:" + ", ".join(best_sensitive))
        if strongest >= 90:
            reasons.append("basis:企業名の近くに漏洩関連語と複数の機微情報種別を検出")
        elif strongest >= 75:
            reasons.append("basis:企業名の近くに漏洩関連語と情報種別を検出")
        elif strongest >= 55:
            reasons.append("basis:企業名の近くに漏洩関連語または複数の情報種別を検出")
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
