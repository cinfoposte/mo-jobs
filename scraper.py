#!/usr/bin/env python3
"""
UNjobs RSS Feed Scraper
=======================
Scrapes UNjobs.org organisation pages and generates one RSS 2.0 feed per
organisation.  Applies global JPO exclusion and org-specific grade/role
filters defined in config/filters.yml.

Usage:
    python scraper.py
"""

import hashlib
import logging
import os
import re
import sys
import time
import datetime
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree, indent

import requests
import yaml
from bs4 import BeautifulSoup, NavigableString
from dateutil import parser as dateparser

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
FEEDS_DIR = BASE_DIR / "feeds"
MAX_ITEMS_PER_FEED = 200
MAX_PAGES_PER_ORG = 20
REQUEST_TIMEOUT = 30
RETRY_ATTEMPTS = 3
SLEEP_BETWEEN_PAGES = 2.0     # seconds between page fetches
SLEEP_BETWEEN_DETAILS = 1.0   # seconds between detail-page fetches
USER_AGENT = (
    "Mozilla/5.0 (compatible; mo-jobs-rss-bot/1.0; "
    "+https://github.com/cinfoposte/mo-jobs)"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scraper")

# ---------------------------------------------------------------------------
# Helpers – HTTP
# ---------------------------------------------------------------------------
_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT})


def fetch(url: str) -> requests.Response | None:
    """GET *url* with retries and polite back-off."""
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            resp = _session.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return resp
            log.warning("HTTP %s for %s (attempt %d)", resp.status_code, url, attempt)
        except requests.RequestException as exc:
            log.warning("Request error for %s: %s (attempt %d)", url, exc, attempt)
        if attempt < RETRY_ATTEMPTS:
            time.sleep(2 ** attempt)
    return None


# ---------------------------------------------------------------------------
# Helpers – config loading
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
# Helpers – filtering
# ---------------------------------------------------------------------------

def _matches_any(text: str, patterns: list[str]) -> bool:
    """Return True if *text* matches any regex in *patterns* (case-insensitive)."""
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def is_jpo(title: str, description: str, jpo_patterns: list[str]) -> bool:
    """Return True if the vacancy is a JPO (must be excluded globally)."""
    combined = f"{title} {description}"
    return _matches_any(combined, jpo_patterns)


def passes_un_standard(title: str, description: str, profile: dict) -> bool:
    """Apply UN standard filter: must match an include pattern.

    The include rule (P/D grades + UNV) is primary.  Exclusions are secondary
    and must NOT remove posts that matched a P/D grade or UNV pattern.
    Only items that match *neither* P/D nor UNV are subject to exclusion.
    """
    combined = f"{title} {description}"
    include_pats = profile.get("include_patterns", [])
    exclude_pats = profile.get("exclude_patterns", [])

    # Classify which kind of include was matched
    matched_pd = False   # P1-P6, D1-D2, ASG/USG/DSG
    matched_unv = False  # UNV / UN Volunteer

    _unv_keywords = ("UNV", "UN Volunteer", "UN Volunteering")

    for pat in include_pats:
        if re.search(pat, combined, re.IGNORECASE):
            if any(kw in pat for kw in _unv_keywords):
                matched_unv = True
            else:
                matched_pd = True

    # Must match at least one include pattern
    if not matched_pd and not matched_unv:
        return False

    # P/D grades and UNV are authoritative — skip exclusion checks
    if matched_pd or matched_unv:
        return True

    # (Unreachable given the logic above, but kept for safety)
    if _matches_any(combined, exclude_pats):
        return False

    return True


def passes_bank_filter(title: str, description: str, profile: dict) -> bool:
    """Apply bank-specific filter."""
    combined = f"{title} {description}"
    include_pats = profile.get("include_patterns", [])
    exclude_pats = profile.get("exclude_patterns", [])
    permissive = profile.get("permissive", False)

    # Always apply excludes first
    if _matches_any(combined, exclude_pats):
        return False

    # If there are include patterns, check them
    if include_pats:
        if _matches_any(combined, include_pats):
            return True
        # If permissive mode, include even without a grade match
        if permissive:
            return True
        return False

    # No include patterns and not excluded → include (permissive default)
    return True


def apply_filter(title: str, description: str, filter_profile_name: str,
                 filters_cfg: dict) -> bool:
    """Return True if the vacancy should be INCLUDED in the feed."""

    # Global JPO exclusion
    jpo_patterns = filters_cfg.get("global_exclude", {}).get("jpo_patterns", [])
    if is_jpo(title, description, jpo_patterns):
        return False

    # Org-specific filter
    if filter_profile_name == "un_standard":
        profile = filters_cfg.get("un_standard", {})
        return passes_un_standard(title, description, profile)

    # Bank profiles
    profile = filters_cfg.get(filter_profile_name, {})
    if profile:
        return passes_bank_filter(title, description, profile)

    # Unknown profile → include by default
    log.warning("Unknown filter profile '%s', including by default", filter_profile_name)
    return True


# ---------------------------------------------------------------------------
# Scraping – listing pages
# ---------------------------------------------------------------------------

def scrape_listing_page(soup: BeautifulSoup) -> list[dict]:
    """Extract vacancy stubs from one listing page.

    Returns list of dicts with keys: title, url, closing_date.
    """
    items = []
    # Extract closing dates from inline JS
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

        # Try to get closing date via span id
        closing_date = ""
        span = job_div.find("span", id=re.compile(r"j\d+"))
        if span:
            jid = span["id"][1:]  # strip leading 'j'
            closing_date = closing_dates.get(jid, "")

        items.append({
            "title": title,
            "url": url,
            "closing_date": closing_date,
        })
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
            break

        soup = BeautifulSoup(resp.content, "lxml")
        page_items = scrape_listing_page(soup)

        if not page_items:
            log.info("[%s] No jobs on page %d, ending pagination", org_key, page_num)
            break

        new_count = 0
        for item in page_items:
            if item["url"] not in seen_urls:
                seen_urls.add(item["url"])
                all_items.append(item)
                new_count += 1

        log.info("[%s] Page %d: %d jobs (%d new)", org_key, page_num, len(page_items), new_count)

        if new_count == 0:
            break  # all duplicates → we've looped back

        if len(all_items) >= MAX_ITEMS_PER_FEED:
            all_items = all_items[:MAX_ITEMS_PER_FEED]
            break

        time.sleep(SLEEP_BETWEEN_PAGES)

    log.info("[%s] Total listings collected: %d", org_key, len(all_items))
    return all_items


# ---------------------------------------------------------------------------
# Scraping – detail pages
# ---------------------------------------------------------------------------

def scrape_detail_page(url: str) -> dict:
    """Fetch a vacancy detail page and extract description + metadata.

    Returns dict with keys: description, pub_date, original_link.
    """
    result = {"description": "", "pub_date": "", "original_link": ""}
    resp = fetch(url)
    if resp is None:
        return result

    soup = BeautifulSoup(resp.content, "lxml")

    # --- Description ---
    # Try common containers for the job description
    desc_text = ""
    # Look for the main content area
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
    # UNjobs often has a link like "Apply here" or "Original" pointing to the source
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True).lower()
        if any(kw in text for kw in ["apply", "original", "source", "employer"]):
            if href.startswith("http") and "unjobs.org" not in href:
                result["original_link"] = href
                break

    # --- Publication date ---
    # Try to find a date in the page
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
    """Build an RSS 2.0 XML string from filtered items."""
    rss = Element("rss", version="2.0")
    channel = SubElement(rss, "channel")

    SubElement(channel, "title").text = f"{org['display_name']} – Job Vacancies"
    SubElement(channel, "link").text = org["unjobs_url"]
    SubElement(channel, "description").text = (
        f"Latest job vacancies for {org['display_name']} sourced from UNjobs.org. "
        f"JPO positions are excluded."
    )
    SubElement(channel, "language").text = "en"
    SubElement(channel, "lastBuildDate").text = datetime.datetime.now(
        tz=datetime.timezone.utc
    ).strftime("%a, %d %b %Y %H:%M:%S +0000")

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
    import io
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
# Main pipeline
# ---------------------------------------------------------------------------

def process_org(org: dict, filters_cfg: dict) -> None:
    """Full pipeline for one organisation: scrape → filter → write RSS."""
    key = org["key"]
    profile = org.get("filter_profile", "")
    log.info("=" * 60)
    log.info("[%s] Starting: %s", key, org["display_name"])

    # 1. Scrape listing pages
    stubs = scrape_org_listings(org["unjobs_url"], key)
    if not stubs:
        log.warning("[%s] No listings found; writing empty feed", key)
        write_empty_rss(org)
        return

    # 2. Fetch detail pages and apply filters
    filtered_items: list[dict] = []
    for i, stub in enumerate(stubs):
        if len(filtered_items) >= MAX_ITEMS_PER_FEED:
            break

        log.info("[%s] Detail %d/%d: %s", key, i + 1, len(stubs), stub["title"][:60])
        detail = scrape_detail_page(stub["url"])

        title = stub["title"]
        description = detail.get("description", "")

        # Apply filters
        if not apply_filter(title, description, profile, filters_cfg):
            log.debug("[%s] EXCLUDED: %s", key, title[:60])
            continue

        filtered_items.append({
            "title": title,
            "url": stub["url"],
            "original_link": detail.get("original_link", ""),
            "pub_date": detail.get("pub_date", ""),
            "description": description,
            "closing_date": stub.get("closing_date", ""),
        })

        if i < len(stubs) - 1:
            time.sleep(SLEEP_BETWEEN_DETAILS)

    log.info("[%s] Filtered items: %d / %d listings", key, len(filtered_items), len(stubs))

    # 3. Write RSS
    xml_content = build_rss(org, filtered_items)
    write_rss(org, xml_content)


def main() -> None:
    log.info("UNjobs RSS Scraper starting")
    log.info("Base directory: %s", BASE_DIR)

    orgs = load_orgs()
    filters_cfg = load_filters()

    FEEDS_DIR.mkdir(parents=True, exist_ok=True)

    success_count = 0
    fail_count = 0

    for org in orgs:
        try:
            process_org(org, filters_cfg)
            success_count += 1
        except Exception:
            log.exception("[%s] FAILED – continuing with next org", org.get("key", "?"))
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
