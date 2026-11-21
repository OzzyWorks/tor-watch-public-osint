"""Fetch public ransomware leak-site HTML for defensive OSINT.

Only same-host HTML pages are followed. Download/archive/document links and
external links are deliberately excluded; leaked files are never retrieved.
"""
import hashlib
import re
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = "TorWatch-Public-OSINT/0.5"
MAX_DETAIL_PAGES = 5
MAX_HTML_BYTES = 1_000_000
BLOCKED_EXTENSIONS = (
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".sql", ".db",
    ".dump", ".bak", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".csv", ".txt", ".json", ".exe", ".dll", ".iso", ".img",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".mp3",
)
BLOCKED_PATH_PARTS = (
    "/logout", "/login", "/register", "/download", "/file/",
    "/files/", "/attachment", "/uploads/",
)


def _candidate_links(base_url, soup, limit=MAX_DETAIL_PAGES):
    """Return unique same-host HTML-like links, never file downloads."""
    base = urlparse(base_url)
    found = []
    seen = {base_url}
    for anchor in soup.find_all("a", href=True):
        href = (anchor.get("href") or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        target = urljoin(base_url, href)
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or parsed.hostname != base.hostname:
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean in seen:
            continue
        path = parsed.path.lower()
        if path.endswith(BLOCKED_EXTENSIONS):
            continue
        if any(part in path for part in BLOCKED_PATH_PARTS):
            continue
        if clean.rstrip("/") == base_url.rstrip("/"):
            continue
        seen.add(clean)
        label = " ".join(anchor.get_text(" ", strip=True).split())
        found.append((clean, label))
        if len(found) >= limit:
            break
    return found


def _page_text(soup):
    for node in soup(["script", "style", "noscript", "svg"]):
        node.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


def _get_with_retry(session, url, timeout, headers):
    """Retry one transient Tor/network failure; never retry HTTP/content errors."""
    for attempt in range(2):
        try:
            return session.get(
                url, timeout=timeout, headers=headers, allow_redirects=False
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            if attempt == 1:
                raise
            host = urlparse(url).hostname or "unknown host"
            print(f"TorWatch: retrying {host} once after {type(exc).__name__}")
            time.sleep(2)


def _safe_redirect_target(base_url, location):
    """Allow one redirect only when it stays on the same host and remains HTML-like."""
    if not location:
        return None
    base=urlparse(base_url)
    target=urljoin(base_url,location)
    parsed=urlparse(target)
    if parsed.scheme not in ("http","https") or parsed.hostname != base.hostname:
        return None
    path=parsed.path.lower()
    if path.endswith(BLOCKED_EXTENSIONS) or any(part in path for part in BLOCKED_PATH_PARTS):
        return None
    return parsed._replace(fragment="").geturl()


def _get_detail(session, detail_url, timeout, headers):
    """Fetch a detail page without following redirects to other resources or hosts."""
    return session.get(
        detail_url, timeout=timeout, headers=headers, allow_redirects=False
    )


def fetch(url, timeout=20):
    session = requests.Session()
    session.proxies.update({
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    })
    headers = {"User-Agent": USER_AGENT}
    final_url=url
    response = _get_with_retry(session, url, timeout, headers)
    redirect_codes=(301,302,303,307,308)
    if response.status_code in redirect_codes:
        target=_safe_redirect_target(url,response.headers.get("Location",""))
        if not target:
            raise ValueError(f"HTTP redirect {response.status_code} blocked: missing or unsafe same-host Location")
        response=_get_with_retry(session,target,timeout,headers)
        final_url=target
        if response.status_code in redirect_codes or 300 <= response.status_code < 400:
            raise ValueError(f"HTTP redirect chain stopped after one hop (status {response.status_code})")
    elif 300 <= response.status_code < 400:
        raise ValueError(f"Unexpected HTTP {response.status_code} response; no page content")
    response.raise_for_status()
    content_type = response.headers.get("Content-Type", "").lower()
    if content_type and "html" not in content_type:
        raise ValueError("監視対象URLがHTMLを返しません")
    if len(response.content) > MAX_HTML_BYTES:
        raise ValueError("トップページが1MBを超えたため取得を中止")
    soup = BeautifulSoup(response.text, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    chunks = [_page_text(soup)]

    # Inspect a small number of same-host post/detail pages. Never follow
    # external links or links that look like downloadable files.
    for detail_url, label in _candidate_links(final_url, soup):
        try:
            detail = _get_detail(session, detail_url, timeout=(3, 5), headers=headers)
            if detail.status_code != 200:
                continue
            detail_type = detail.headers.get("Content-Type", "").lower()
            if detail_type and "html" not in detail_type:
                continue
            if len(detail.content) > MAX_HTML_BYTES:
                continue
            detail_soup = BeautifulSoup(detail.text, "html.parser")
            detail_title = detail_soup.title.get_text(" ", strip=True) if detail_soup.title else ""
            detail_body = _page_text(detail_soup)
            if label or detail_title or detail_body:
                chunks.append(" ".join(x for x in (label, detail_title, detail_body) if x))
        except requests.RequestException:
            # A single stale post must not prevent the landing page being scanned.
            continue

    # Preserve page boundaries so risk evidence on one detail page cannot
    # be attributed to a company mentioned on another page.
    text = "\n\n[TORWATCH_PAGE_BOUNDARY]\n\n".join(x for x in chunks if x)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return title, text, digest
