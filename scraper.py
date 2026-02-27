#!/usr/bin/env python3
"""
UNjobs RSS Feed Scraper
=======================
Scrapes UNjobs.org organisation pages and generates one RSS 2.0 feed per
organisation.  Applies global JPO exclusion and org-specific grade/role
filters defined in config/filters.yml.

Filtering is performed on the FULL TEXT extracted from each UNjobs vacancy
detail page (not just the title/snippet).  For UN org profiles, if no grade
is detected in the UNjobs detail, a fallback fetch of the original/source
link is attempted.

Usage:
    python scraper.py
"""

import csv
import hashlib
import io
import logging
import re
import sys
import time
import datetime
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, ElementTree, indent

import requests
import yaml
from bs4 import BeautifulSoup
from dateutil import parser as dateparser

# curl_cffi impersonates a real Chrome browser at the TLS level.
# Without it, Cloudflare detects Python's requests library by its
# TLS fingerprint and returns 403 regardless of HTTP headers.
try:
    from curl_cffi import requests as curl_requests
    _HAVE_CURL_CFFI = True
except ImportError:
    _HAVE_CURL_CFFI = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
FEEDS_DIR = BASE_DIR / "feeds"
DEBUG_DIR = BASE_DIR / "debug"
MAX_ITEMS_PER_FEED = 200
MAX_PAGES_PER_ORG = 20
REQUEST_TIMEOUT = 30
ORIGINAL_LINK_TIMEOUT = 15
RETRY_ATTEMPTS = 3
SLEEP_BETWEEN_PAGES = 2.0     # seconds between page fetches
SLEEP_BETWEEN_DETAILS = 1.0   # seconds between detail-page fetches

# Realistic browser headers – UNjobs blocks requests that look automated.
# Using a standard Chrome User-Agent and common browser headers prevents
# Cloudflare/bot-detection from serving challenge pages instead of content.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
BROWSER_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

FEEDS_BASE_URL = "https://cinfoposte.github.io/mo-jobs"
ATOM_NS = "http://www.w3.org/2005/Atom"

# Register atom namespace so ElementTree uses 'atom:' prefix
ET.register_namespace("atom", ATOM_NS)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scraper")

# ---------------------------------------------------------------------------
# Helpers - HTTP
# ---------------------------------------------------------------------------

# Prefer curl_cffi: it impersonates Chrome's TLS fingerprint so Cloudflare
# doesn't block us with 403.  Fall back to plain requests if unavailable.
if _HAVE_CURL_CFFI:
    _session = curl_requests.Session(impersonate="chrome")
else:
    _session = requests.Session()
    _session.headers.update(BROWSER_HEADERS)


def _is_challenge_page(resp: requests.Response) -> bool:
    """Detect Cloudflare or bot-challenge pages that return 200 but no real content.

    IMPORTANT: Only match on patterns specific to challenge/interstitial pages.
    Do NOT match on generic "cloudflare" — it appears on every page served
    through Cloudflare CDN (in script URLs, Ray IDs, footers, etc.).
    """
    text = resp.text[:5000].lower()
    # These patterns only appear on actual challenge/block pages, not normal content
    challenge_markers = [
        "checking your browser before accessing",
        "cf-browser-verification",
        "challenge-platform",
        "_cf_chl",
        "cf-challenge",
        "managed challenge",
        "turnstile",
        # Cloudflare "Just a moment" interstitial (but NOT just "moment" alone)
        "just a moment</title>",
        "enable javascript and cookies to continue",
    ]
    return any(m in text for m in challenge_markers)


def fetch(url: str) -> requests.Response | None:
    """GET *url* with retries and polite back-off."""
    last_resp = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            resp = _session.get(url, timeout=REQUEST_TIMEOUT)
            last_resp = resp
            if resp.status_code == 200:
                if _is_challenge_page(resp):
                    log.warning(
                        "Bot challenge page detected for %s (attempt %d)",
                        url, attempt,
                    )
                    # Fall through to retry with back-off
                else:
                    return resp
            else:
                log.warning("HTTP %s for %s (attempt %d)", resp.status_code, url, attempt)
        except requests.RequestException as exc:
            log.warning("Request error for %s: %s (attempt %d)", url, exc, attempt)
        if attempt < RETRY_ATTEMPTS:
            time.sleep(2 ** attempt)
    # Log details about the failure for debugging
    if last_resp is not None:
        title = ""
        try:
            from bs4 import BeautifulSoup as _BS
            _s = _BS(last_resp.text[:3000], "lxml")
            _t = _s.find("title")
            title = _t.get_text(strip=True) if _t else ""
        except Exception:
            pass
        log.warning(
            "fetch() failed after %d attempts for %s – "
            "last status: %d, page title: '%s', body length: %d",
            RETRY_ATTEMPTS, url, last_resp.status_code, title[:80], len(last_resp.text),
        )
        # Save the failed response for offline debugging
        _save_fetch_debug(url, last_resp)
    return None


def _save_fetch_debug(url: str, resp: requests.Response) -> None:
    """Save failed response HTML so we can inspect what the site returned."""
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    # Use a sanitised filename from the URL
    slug = re.sub(r"[^a-z0-9]+", "_", url.lower())[-60:]
    path = DEBUG_DIR / f"fetch_fail_{slug}.html"
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(f"<!-- URL: {url} -->\n")
            fh.write(f"<!-- Status: {resp.status_code} -->\n")
            fh.write(resp.text[:200_000])
        log.info("Saved failed fetch response to %s", path)
    except Exception:
        pass


def fetch_best_effort(url: str) -> requests.Response | None:
    """Single-attempt fetch with shorter timeout (for fallback original links)."""
    try:
        resp = _session.get(url, timeout=ORIGINAL_LINK_TIMEOUT, allow_redirects=True)
        if resp.status_code == 200:
            return resp
        log.debug("Fallback fetch HTTP %s for %s", resp.status_code, url)
    except requests.RequestException as exc:
        log.debug("Fallback fetch error for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------------
# Helpers - config loading
# ---------------------------------------------------------------------------

def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_orgs() -> list[dict]:
    data = load_yaml(CONFIG_DIR / "orgs.yml")
    return data.get("organisations", [])


def load_filters() -> dict:
    return load_yaml(CONFIG_DIR / "filters.yml")


# ---------------------------------------------------------------------------
# Helpers - text extraction
# ---------------------------------------------------------------------------

def extract_full_text(soup: BeautifulSoup) -> str:
    """Extract all meaningful plaintext from the page body for filtering.

    Skips script, style, nav, and noscript elements.
    """
    texts = []
    body = soup.find("main") or soup.find("article") or soup.find("body")
    if body:
        for element in body.find_all(string=True):
            if element.parent.name in ("script", "style", "nav", "noscript"):
                continue
            text = element.strip()
            if text:
                texts.append(text)
    return " ".join(texts)


def build_text_for_filter(title: str, detail_full_text: str) -> str:
    """Build the canonical text used for all filter matching.

    Returns lowercased combined text of title + detail page plaintext.
    """
    return f"{title}\n{detail_full_text}".lower()


# ---------------------------------------------------------------------------
# Helpers - filtering
# ---------------------------------------------------------------------------

def _matches_any(text: str, patterns: list[str]) -> bool:
    """Return True if *text* matches any regex in *patterns* (case-insensitive)."""
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def is_jpo(text_for_filter: str, jpo_patterns: list[str]) -> bool:
    """Return True if the vacancy is a JPO (must be excluded globally)."""
    return _matches_any(text_for_filter, jpo_patterns)


def _classify_un_standard(text_for_filter: str, profile: dict) -> tuple[bool, str]:
    """Apply UN standard filter and return (included, reason).

    Reasons: 'grade_match', 'unv_match', 'intern_consultant', 'no_grade'.
    """
    include_pats = profile.get("include_patterns", [])
    exclude_pats = profile.get("exclude_patterns", [])

    matched_pd = False   # P1-P6, D1-D2, ASG/USG/DSG
    matched_unv = False  # UNV / UN Volunteer

    _unv_keywords = ("UNV", "UN Volunteer", "UN Volunteering")

    for pat in include_pats:
        if re.search(pat, text_for_filter, re.IGNORECASE):
            if any(kw in pat for kw in _unv_keywords):
                matched_unv = True
            else:
                matched_pd = True

    # P/D grades and UNV are authoritative - include regardless of excludes
    if matched_pd:
        return True, "grade_match"
    if matched_unv:
        return True, "unv_match"

    # No include match - check excludes for reason classification
    if _matches_any(text_for_filter, exclude_pats):
        return False, "intern_consultant"

    # No include match, no exclude match - unknown grade
    return False, "no_grade"


def _classify_bank(text_for_filter: str, profile: dict) -> tuple[bool, str]:
    """Apply bank-specific filter and return (included, reason)."""
    include_pats = profile.get("include_patterns", [])
    exclude_pats = profile.get("exclude_patterns", [])
    permissive = profile.get("permissive", False)

    # Always apply excludes first
    if _matches_any(text_for_filter, exclude_pats):
        return False, "bank_exclude"

    # If there are include patterns, check them
    if include_pats:
        if _matches_any(text_for_filter, include_pats):
            return True, "bank_include"
        if permissive:
            return True, "bank_permissive"
        return False, "bank_no_match"

    # No include patterns and not excluded - include (permissive default)
    return True, "bank_default"


def apply_filter(text_for_filter: str, filter_profile_name: str,
                 filters_cfg: dict) -> tuple[bool, str]:
    """Return (included, reason) for the vacancy.

    *text_for_filter* should be the output of build_text_for_filter().
    """
    # Global JPO exclusion
    jpo_patterns = filters_cfg.get("global_exclude", {}).get("jpo_patterns", [])
    if is_jpo(text_for_filter, jpo_patterns):
        return False, "jpo"

    # Org-specific filter
    if filter_profile_name == "un_standard":
        profile = filters_cfg.get("un_standard", {})
        return _classify_un_standard(text_for_filter, profile)

    # Bank profiles
    profile = filters_cfg.get(filter_profile_name, {})
    if profile:
        return _classify_bank(text_for_filter, profile)

    # Unknown profile - include by default
    log.warning("Unknown filter profile '%s', including by default", filter_profile_name)
    return True, "unknown_profile"


# ---------------------------------------------------------------------------
# Scraping - listing pages
# ---------------------------------------------------------------------------

def _save_listing_debug_snippet(org_key: str, html_text: str) -> None:
    """Save first 200 KB of a listing page HTML for offline debugging."""
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    snippet_path = DEBUG_DIR / f"{org_key}_listing_snippet.html"
    with open(snippet_path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(html_text[:200_000])
    log.warning(
        "[%s] Wrote listing debug snippet to %s (%d bytes)",
        org_key, snippet_path, min(len(html_text), 200_000),
    )

# Regex for UNjobs vacancy URLs: /vacancies/ followed by digits
_VACANCY_URL_RE = re.compile(r"/vacancies/(\d+)")

# Paths to ignore when scanning for vacancy links (navigation, non-job pages)
_IGNORE_HREF_PARTS = (
    "/organizations/", "/duty_stations/", "/countries/", "/themes/",
    "/grades/", "/skills/", "/tags/", "/closing", "/privacy",
    "/about", "/contact",
)


def scrape_listing_page(soup: BeautifulSoup) -> list[dict]:
    """Extract vacancy stubs from one listing page.

    Primary strategy: find all <a> tags whose href matches /vacancies/DIGITS.
    This is resilient to HTML structure / class-name changes on UNjobs.

    Fallback: try legacy div.job + a.jtitle selectors.

    Returns list of dicts with keys: title, url, closing_date.
    """
    items = []
    seen_hrefs: set[str] = set()

    # --- Strategy 1: robust href-based extraction --------------------------
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]

        # Must be a vacancy URL
        if not _VACANCY_URL_RE.search(href):
            continue

        # Skip navigation / non-job links
        if any(part in href for part in _IGNORE_HREF_PARTS):
            continue

        # Normalise to absolute URL
        if not href.startswith("http"):
            href = f"https://unjobs.org{href}"

        # Deduplicate within a single page
        if href in seen_hrefs:
            continue
        seen_hrefs.add(href)

        title = a_tag.get_text(strip=True)
        # Skip anchors with no meaningful text (icons, images, etc.)
        if not title or len(title) < 3:
            continue

        items.append({
            "title": title,
            "url": href,
            "closing_date": "",  # will be enriched from detail page
        })

    if items:
        log.info("  Listing parser: found %d vacancy links via href matching", len(items))
        return items

    # --- Strategy 2: legacy div.job + a.jtitle (fallback) ------------------
    # Extract closing dates from inline JS (old UNjobs feature)
    closing_dates: dict[str, str] = {}
    script_el = soup.find("script", string=re.compile(r"var j\d+i\s*=\s*new Date"))
    if script_el and script_el.string:
        for match in re.finditer(r"var j(\d+)i\s*=\s*new Date\((\d+)\)", script_el.string):
            job_id_suffix, ts = match.groups()
            try:
                dt = datetime.datetime.fromtimestamp(int(ts) / 1000, tz=datetime.timezone.utc)
                closing_dates[job_id_suffix] = dt.strftime("%Y-%m-%d")
            except (ValueError, OSError):
                pass

    jobs = soup.find_all("div", class_="job")
    for job_div in jobs:
        a_tag = job_div.find("a", class_="jtitle")
        if not a_tag:
            continue
        title = a_tag.get_text(strip=True)
        url = a_tag.get("href", "")
        if url and not url.startswith("http"):
            url = f"https://unjobs.org{url}"

        closing_date = ""
        span = job_div.find("span", id=re.compile(r"j\d+"))
        if span:
            jid = span["id"][1:]
            closing_date = closing_dates.get(jid, "")

        items.append({
            "title": title,
            "url": url,
            "closing_date": closing_date,
        })

    if items:
        log.info("  Listing parser: found %d stubs via legacy div.job selectors", len(items))

    return items


def scrape_org_listings(base_url: str, org_key: str) -> list[dict]:
    """Paginate through the org listing and collect all vacancy stubs."""
    all_items: list[dict] = []
    seen_urls: set[str] = set()

    for page_num in range(0, MAX_PAGES_PER_ORG):
        page_url = base_url if page_num == 0 else f"{base_url}/{page_num}"
        log.info("[%s] Fetching listing page %d: %s", org_key, page_num, page_url)
        resp = fetch(page_url)
        if resp is None:
            log.warning("[%s] Failed to fetch page %d, stopping pagination", org_key, page_num)
            # Try to save whatever the last HTTP response was for debugging
            # (fetch() already logged the details)
            break

        soup = BeautifulSoup(resp.content, "lxml")
        page_items = scrape_listing_page(soup)

        if not page_items:
            # Diagnostic: log why no jobs were found
            title_el = soup.find("title")
            page_title = title_el.get_text(strip=True) if title_el else "(no title)"
            body_len = len(soup.get_text())
            div_count = len(soup.find_all("div"))
            a_count = len(soup.find_all("a", href=True))
            log.warning(
                "[%s] No jobs found on page %d. Page title: '%s', "
                "body text length: %d, div count: %d, anchor count: %d",
                org_key, page_num, page_title[:80], body_len, div_count, a_count,
            )
            # Save HTML snippet for offline debugging
            _save_listing_debug_snippet(org_key, resp.text)
            break

        new_count = 0
        for item in page_items:
            if item["url"] not in seen_urls:
                seen_urls.add(item["url"])
                all_items.append(item)
                new_count += 1

        log.info("[%s] Page %d: %d jobs (%d new)", org_key, page_num, len(page_items), new_count)

        if new_count == 0:
            break  # all duplicates - we've looped back

        if len(all_items) >= MAX_ITEMS_PER_FEED:
            all_items = all_items[:MAX_ITEMS_PER_FEED]
            break

        time.sleep(SLEEP_BETWEEN_PAGES)

    log.info("[%s] Total listings collected: %d", org_key, len(all_items))
    return all_items


# ---------------------------------------------------------------------------
# Scraping - detail pages
# ---------------------------------------------------------------------------

def scrape_detail_page(url: str) -> dict:
    """Fetch a vacancy detail page and extract description + metadata.

    Returns dict with keys: description, full_text, pub_date, original_link.
    """
    result = {"description": "", "full_text": "", "pub_date": "", "original_link": ""}
    resp = fetch(url)
    if resp is None:
        return result

    soup = BeautifulSoup(resp.content, "lxml")

    # --- Full text for filtering (extract before any DOM modification) ---
    result["full_text"] = extract_full_text(soup)

    # --- Description (truncated for RSS snippet) ---
    desc_text = ""
    for selector in [
        ("div", {"class": "jd"}),
        ("div", {"class": "job-description"}),
        ("div", {"class": "content"}),
        ("article",),
    ]:
        el = soup.find(*selector) if len(selector) > 1 else soup.find(selector[0])
        if el:
            desc_text = el.get_text(separator=" ", strip=True)
            break

    # Fallback: grab all paragraph text from main area
    if not desc_text:
        main = soup.find("main") or soup.find("body")
        if main:
            paragraphs = main.find_all("p")
            desc_text = " ".join(p.get_text(strip=True) for p in paragraphs[:10])

    # Truncate to reasonable length for RSS snippet
    if len(desc_text) > 1000:
        desc_text = desc_text[:997] + "..."
    result["description"] = desc_text

    # --- Original employer link ---
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True).lower()
        if any(kw in text for kw in ["apply", "original", "source", "employer"]):
            if href.startswith("http") and "unjobs.org" not in href:
                result["original_link"] = href
                break

    # --- Publication date ---
    for selector in [
        ("span", {"class": "date"}),
        ("time",),
        ("span", {"class": "posted"}),
    ]:
        el = soup.find(*selector) if len(selector) > 1 else soup.find(selector[0])
        if el:
            date_text = el.get("datetime", "") or el.get_text(strip=True)
            if date_text:
                try:
                    dt = dateparser.parse(date_text)
                    if dt:
                        result["pub_date"] = dt.strftime("%a, %d %b %Y %H:%M:%S +0000")
                        break
                except (ValueError, OverflowError):
                    pass

    return result


def fetch_original_link_text(url: str) -> str:
    """Best-effort fetch of original job posting for grade detection.

    Uses a shorter timeout and single attempt.  Returns extracted
    plaintext or empty string on any failure.
    """
    resp = fetch_best_effort(url)
    if resp is None:
        return ""
    try:
        soup = BeautifulSoup(resp.content, "lxml")
        return extract_full_text(soup)
    except Exception as exc:
        log.debug("Error parsing original link %s: %s", url, exc)
        return ""


# ---------------------------------------------------------------------------
# RSS generation
# ---------------------------------------------------------------------------

def _cdata_escape(text: str) -> str:
    """Minimal XML-safe escaping for text content."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def stable_guid(url: str) -> str:
    """Produce a stable GUID from the canonical URL."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]


def build_rss(org: dict, items: list[dict]) -> str:
    """Build an RSS 2.0 XML string from filtered items.

    Includes <atom:link rel="self"> for feed validator compliance.
    """
    rss = Element("rss", version="2.0")
    channel = SubElement(rss, "channel")

    SubElement(channel, "title").text = f"{org['display_name']} \u2013 Job Vacancies"
    SubElement(channel, "link").text = org["unjobs_url"]
    SubElement(channel, "description").text = (
        f"Latest job vacancies for {org['display_name']} sourced from UNjobs.org. "
        f"JPO positions are excluded."
    )
    SubElement(channel, "language").text = "en"
    SubElement(channel, "lastBuildDate").text = datetime.datetime.now(
        tz=datetime.timezone.utc
    ).strftime("%a, %d %b %Y %H:%M:%S +0000")

    # atom:link self (validator recommendation)
    atom_link = SubElement(channel, f"{{{ATOM_NS}}}link")
    atom_link.set("href", f"{FEEDS_BASE_URL}/{org['output_file']}")
    atom_link.set("rel", "self")
    atom_link.set("type", "application/rss+xml")

    for it in items:
        item_el = SubElement(channel, "item")
        SubElement(item_el, "title").text = it.get("title", "Untitled")
        link = it.get("original_link") or it.get("url", "")
        SubElement(item_el, "link").text = link
        SubElement(item_el, "guid", isPermaLink="false").text = stable_guid(
            it.get("url", link)
        )

        pub = it.get("pub_date", "")
        if not pub:
            pub = datetime.datetime.now(tz=datetime.timezone.utc).strftime(
                "%a, %d %b %Y %H:%M:%S +0000"
            )
        SubElement(item_el, "pubDate").text = pub

        desc = it.get("description", "")
        SubElement(item_el, "description").text = _cdata_escape(desc) if desc else ""

    # Pretty-print
    indent(rss, space="  ")
    tree = ElementTree(rss)

    # Write to string
    buf = io.BytesIO()
    tree.write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue().decode("utf-8")


def write_rss(org: dict, xml_content: str) -> None:
    """Write RSS XML to the output file."""
    output_path = BASE_DIR / org["output_file"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(xml_content)
    log.info("[%s] Wrote %s", org["key"], output_path)


def write_empty_rss(org: dict) -> None:
    """Write a valid but empty RSS scaffold."""
    xml_content = build_rss(org, [])
    write_rss(org, xml_content)


# ---------------------------------------------------------------------------
# Debug artifacts
# ---------------------------------------------------------------------------

def write_debug_csv(org_key: str, excluded_items: list[dict]) -> None:
    """Write a CSV of excluded items for debugging (up to 50 items)."""
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = DEBUG_DIR / f"{org_key}_excluded_sample.csv"
    rows = excluded_items[:50]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["org_key", "title", "unjobs_url", "original_url", "exclusion_reason"])
        for row in rows:
            writer.writerow([
                row.get("org_key", org_key),
                row.get("title", ""),
                row.get("unjobs_url", ""),
                row.get("original_url", ""),
                row.get("exclusion_reason", ""),
            ])
    log.info("[%s] Debug CSV: %s (%d excluded items)", org_key, csv_path, len(rows))


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def _log_counts(key: str, counts: dict) -> None:
    """Log filtering summary counts for one org."""
    log.info("[%s] --- Filter Summary ---", key)
    for label, value in counts.items():
        log.info("[%s]   %-30s %d", key, label, value)


def process_org(org: dict, filters_cfg: dict) -> None:
    """Full pipeline for one organisation: scrape -> filter -> write RSS."""
    key = org["key"]
    profile_name = org.get("filter_profile", "")
    log.info("=" * 60)
    log.info("[%s] Starting: %s", key, org["display_name"])

    # Counters for summary
    counts = {
        "listings_found": 0,
        "details_fetched_ok": 0,
        "included": 0,
        "excluded_by_jpo": 0,
        "excluded_by_intern_consultant": 0,
        "excluded_by_grade": 0,
        "excluded_unknown_grade": 0,
        "errors": 0,
    }

    # 1. Scrape listing pages
    stubs = scrape_org_listings(org["unjobs_url"], key)
    counts["listings_found"] = len(stubs)

    if not stubs:
        log.warning("[%s] No listings found; writing empty feed", key)
        write_empty_rss(org)
        write_debug_csv(key, [])
        _log_counts(key, counts)
        return

    # 2. Fetch detail pages and apply filters
    filtered_items: list[dict] = []
    excluded_items: list[dict] = []

    for i, stub in enumerate(stubs):
        if len(filtered_items) >= MAX_ITEMS_PER_FEED:
            break

        log.info("[%s] Detail %d/%d: %s", key, i + 1, len(stubs), stub["title"][:60])
        detail = scrape_detail_page(stub["url"])

        detail_ok = bool(detail.get("full_text") or detail.get("description"))
        if detail_ok:
            counts["details_fetched_ok"] += 1
        else:
            counts["errors"] += 1
            log.warning("[%s]   Failed to fetch detail page: %s", key, stub["url"])

        title = stub["title"]
        full_text = detail.get("full_text", "")
        original_link = detail.get("original_link", "")
        text_for_filter = build_text_for_filter(title, full_text)

        # Apply filters on title + full detail text
        included, reason = apply_filter(text_for_filter, profile_name, filters_cfg)

        # Fallback: for UN standard orgs, if no grade found, try original link
        if (not included and reason == "no_grade"
                and profile_name == "un_standard" and original_link):
            log.info("[%s]   No grade in UNjobs detail, trying original link: %s",
                     key, original_link[:80])
            orig_text = fetch_original_link_text(original_link)
            if orig_text:
                extended_filter_text = build_text_for_filter(
                    title, full_text + "\n" + orig_text
                )
                included, reason = apply_filter(
                    extended_filter_text, profile_name, filters_cfg
                )
                if included:
                    log.info("[%s]   Grade found via original link - INCLUDED", key)
            # If still no grade after fallback, mark as unknown_grade
            if not included and reason == "no_grade":
                reason = "unknown_grade"

        if not included:
            # Map reason to counter key
            reason_counter = {
                "jpo": "excluded_by_jpo",
                "intern_consultant": "excluded_by_intern_consultant",
                "no_grade": "excluded_by_grade",
                "unknown_grade": "excluded_unknown_grade",
                "bank_exclude": "excluded_by_grade",
                "bank_no_match": "excluded_by_grade",
            }
            counts[reason_counter.get(reason, "excluded_by_grade")] += 1

            excluded_items.append({
                "org_key": key,
                "title": title,
                "unjobs_url": stub["url"],
                "original_url": original_link,
                "exclusion_reason": reason,
            })
            log.info("[%s]   EXCLUDED (%s): %s", key, reason, title[:60])

            if i < len(stubs) - 1:
                time.sleep(SLEEP_BETWEEN_DETAILS)
            continue

        counts["included"] += 1
        filtered_items.append({
            "title": title,
            "url": stub["url"],
            "original_link": original_link,
            "pub_date": detail.get("pub_date", ""),
            "description": detail.get("description", ""),
            "closing_date": stub.get("closing_date", ""),
        })

        if i < len(stubs) - 1:
            time.sleep(SLEEP_BETWEEN_DETAILS)

    # 3. Log summary
    _log_counts(key, counts)

    # 4. Write debug CSV
    write_debug_csv(key, excluded_items)

    # 5. Write RSS
    log.info("[%s] Filtered items: %d / %d listings", key, len(filtered_items), len(stubs))
    xml_content = build_rss(org, filtered_items)
    write_rss(org, xml_content)


def main() -> None:
    log.info("UNjobs RSS Scraper starting")
    log.info("Base directory: %s", BASE_DIR)

    orgs = load_orgs()
    filters_cfg = load_filters()

    FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)

    success_count = 0
    fail_count = 0

    for org in orgs:
        try:
            process_org(org, filters_cfg)
            success_count += 1
        except Exception:
            log.exception("[%s] FAILED - continuing with next org", org.get("key", "?"))
            # Write empty feed so the file still exists
            try:
                write_empty_rss(org)
            except Exception:
                log.exception("[%s] Could not even write empty feed", org.get("key", "?"))
            fail_count += 1

    log.info("=" * 60)
    log.info("Done. Success: %d  Failed: %d  Total: %d", success_count, fail_count, len(orgs))

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
