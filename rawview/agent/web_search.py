"""
Read-only web search for the agent.

Four providers, chosen by ``RAWVIEW_SEARCH_PROVIDER`` or picked automatically in this order:

* **wormt** - a WormT instance (``WORMT_API_URL`` + ``WORMT_API_KEY``). BM25 over its own crawl.
* **brave** - the Brave Search API (``BRAVE_SEARCH_API_KEY``).
* **searxng** - any SearXNG instance with the JSON format enabled (``SEARXNG_URL``).
* **duckduckgo** - DuckDuckGo's HTML results, scraped. No key, no configuration, so it is what
  runs when nothing is set up.

This used to call DuckDuckGo's instant-answer API, which is not a search engine: it answers with
an encyclopedia abstract and disambiguation links, and for most real queries ("CVE-2024-3094
xz backdoor", an error string out of a binary) it returns nothing at all. Every provider here
returns ranked web results instead.
"""

from __future__ import annotations

import html as html_module
import ipaddress
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_MAX_QUERY_LEN = 400
_MAX_HTTP_BYTES = 400_000
_FETCH_PAGE_BYTES = 48_000
_HTTP_TIMEOUT_S = 14.0
_USER_AGENT = "RawView/0.1 (reverse-engineering assistant; web search)"
# What a browser sends, for the one provider that serves a results page rather than an API.
_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

PROVIDERS = ("wormt", "brave", "searxng", "duckduckgo")


class SearchProviderError(RuntimeError):
    """A provider could not answer. The caller falls through to the next one."""


def _host_blocked(hostname: str | None) -> bool:
    if not hostname:
        return True
    h = hostname.lower().strip(".")
    if h in ("localhost", "localhost.localdomain"):
        return True
    if h.endswith((".local", ".internal")):
        return True
    if h in ("0.0.0.0",):
        return True
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return True
    except ValueError:
        pass
    return False


def is_safe_public_url(url: str) -> bool:
    """For URLs that came out of a search result or a model, which must not reach the LAN."""
    try:
        p = urllib.parse.urlparse(url.strip())
    except Exception:  # noqa: BLE001 - any parse failure means "not a URL we will fetch"
        return False
    if p.scheme not in ("http", "https") or not p.netloc:
        return False
    return not _host_blocked(p.hostname)


def _is_valid_endpoint(url: str) -> bool:
    """
    For the search endpoint itself, which the user configured.

    Deliberately weaker than :func:`is_safe_public_url`: a WormT or SearXNG instance on
    ``127.0.0.1:8080`` or a LAN box is the normal case, and refusing to talk to it would make the
    setting useless. The SSRF guard still applies to every URL those services hand back.
    """
    try:
        p = urllib.parse.urlparse(url.strip())
    except Exception:  # noqa: BLE001 - as above
        return False
    return p.scheme in ("http", "https") and bool(p.netloc)


def _settings() -> Any:
    from rawview.config import load_settings

    return load_settings()


def _http_get(url: str, *, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT, **(headers or {})}, method="GET"
    )
    try:
        # The URL is either a configured endpoint or one this module built, never model input.
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
            return resp.read(_MAX_HTTP_BYTES)
    except urllib.error.HTTPError as e:
        raise SearchProviderError(f"http_{e.code}") from e
    except urllib.error.URLError as e:
        raise SearchProviderError(f"network_error: {e.reason}") from e
    except OSError as e:
        raise SearchProviderError(f"io_error: {e}") from e


def _http_get_json(url: str, *, headers: dict[str, str] | None = None) -> Any:
    raw = _http_get(url, headers=headers)
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise SearchProviderError(f"bad_json: {e}") from e


def _clean_text(value: object, limit: int = 1200) -> str:
    """Unescape entities, drop tags and control characters, collapse whitespace."""
    text = html_module.unescape(str(value or ""))
    text = re.sub(r"<[^>]+>", "", text)
    # WormT wraps matched terms in U+0001/U+0002 (SQLite snippet() markers); plain text here.
    text = text.replace("\u0001", "").replace("\u0002", "")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


# -- providers ------------------------------------------------------------------------


def _search_wormt(query: str, max_results: int, s: Any) -> tuple[list[dict[str, str]], dict[str, Any]]:
    base = str(getattr(s, "wormt_api_url", "") or "").strip().rstrip("/")
    if not base:
        raise SearchProviderError("WORMT_API_URL is not set")
    if not _is_valid_endpoint(base):
        raise SearchProviderError(f"WORMT_API_URL is not a valid http(s) URL: {base}")
    safe = str(getattr(s, "wormt_safe_search", "mid") or "mid").strip().lower()
    if safe not in ("off", "mid", "all"):
        safe = "mid"
    url = f"{base}/api/search?" + urllib.parse.urlencode(
        {"q": query, "top_k": max_results, "safe": safe}
    )
    headers = {"Accept": "application/json"}
    key = str(getattr(s, "wormt_api_key", "") or "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = _http_get_json(url, headers=headers)
    if not isinstance(data, dict):
        raise SearchProviderError("unexpected response shape")
    rows: list[dict[str, str]] = []
    for hit in data.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        u = str(hit.get("url") or "").strip()
        if not u or not is_safe_public_url(u):
            continue
        row = {
            "title": _clean_text(hit.get("title"), 300) or u,
            "url": u,
            "snippet": _clean_text(hit.get("snippet"), 800),
        }
        if hit.get("domain"):
            row["domain"] = _clean_text(hit.get("domain"), 120)
        if hit.get("indexed_at"):
            row["indexed_at"] = str(hit.get("indexed_at"))
        rows.append(row)
    meta: dict[str, Any] = {}
    if data.get("did_you_mean"):
        meta["did_you_mean"] = _clean_text(data.get("did_you_mean"), 200)
    return rows, meta


def _search_brave(query: str, max_results: int, s: Any) -> tuple[list[dict[str, str]], dict[str, Any]]:
    key = str(getattr(s, "brave_search_api_key", "") or "").strip()
    if not key:
        raise SearchProviderError("BRAVE_SEARCH_API_KEY is not set")
    url = "https://api.search.brave.com/res/v1/web/search?" + urllib.parse.urlencode(
        {"q": query, "count": max_results}
    )
    data = _http_get_json(
        url, headers={"Accept": "application/json", "X-Subscription-Token": key}
    )
    rows: list[dict[str, str]] = []
    results = ((data or {}).get("web") or {}).get("results") or []
    for hit in results:
        if not isinstance(hit, dict):
            continue
        u = str(hit.get("url") or "").strip()
        if not u or not is_safe_public_url(u):
            continue
        rows.append(
            {
                "title": _clean_text(hit.get("title"), 300) or u,
                "url": u,
                "snippet": _clean_text(hit.get("description"), 800),
            }
        )
    return rows, {}


def _search_searxng(query: str, max_results: int, s: Any) -> tuple[list[dict[str, str]], dict[str, Any]]:
    base = str(getattr(s, "searxng_url", "") or "").strip().rstrip("/")
    if not base:
        raise SearchProviderError("SEARXNG_URL is not set")
    if not _is_valid_endpoint(base):
        raise SearchProviderError(f"SEARXNG_URL is not a valid http(s) URL: {base}")
    url = f"{base}/search?" + urllib.parse.urlencode({"q": query, "format": "json"})
    data = _http_get_json(url, headers={"Accept": "application/json"})
    rows: list[dict[str, str]] = []
    for hit in (data or {}).get("results") or []:
        if not isinstance(hit, dict):
            continue
        u = str(hit.get("url") or "").strip()
        if not u or not is_safe_public_url(u):
            continue
        rows.append(
            {
                "title": _clean_text(hit.get("title"), 300) or u,
                "url": u,
                "snippet": _clean_text(hit.get("content"), 800),
            }
        )
        if len(rows) >= max_results:
            break
    return rows, {}


_DDG_RESULT_RE = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
)
_DDG_SNIPPET_RE = re.compile(
    r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
)


def _unwrap_ddg_link(href: str) -> str:
    """DuckDuckGo hands back ``//duckduckgo.com/l/?uddg=<escaped target>`` redirect links."""
    if href.startswith("//"):
        href = "https:" + href
    try:
        parsed = urllib.parse.urlparse(href)
    except Exception:  # noqa: BLE001 - an unparseable href is used as-is and filtered later
        return href
    if "duckduckgo.com" in (parsed.hostname or "") and parsed.path.startswith("/l/"):
        target = urllib.parse.parse_qs(parsed.query).get("uddg", [""])[0]
        if target:
            return target
    return href


def _search_duckduckgo(query: str, max_results: int, _s: Any) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """
    Scrape DuckDuckGo's no-JavaScript results page.

    This is the fallback precisely because it is scraping: no key is needed, but the markup is
    theirs to change. Configure WormT, Brave or SearXNG for something that will not move.
    """
    url = "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
    raw = _http_get(url, headers={"User-Agent": _BROWSER_UA, "Accept": "text/html"})
    page = raw.decode("utf-8", errors="replace")
    snippets = [_clean_text(m, 800) for m in _DDG_SNIPPET_RE.findall(page)]
    rows: list[dict[str, str]] = []
    for i, (href, title) in enumerate(_DDG_RESULT_RE.findall(page)):
        u = _unwrap_ddg_link(html_module.unescape(href))
        if not is_safe_public_url(u):
            continue
        rows.append(
            {
                "title": _clean_text(title, 300) or u,
                "url": u,
                "snippet": snippets[i] if i < len(snippets) else "",
            }
        )
        if len(rows) >= max_results:
            break
    if not rows:
        # DuckDuckGo answers a suspected scraper with an anomaly/challenge page that is a valid
        # 200 and contains no results at all. Say that plainly rather than "nothing matched",
        # which would send someone looking for a better query instead of a better provider.
        if "anomaly" in page.lower() or "challenge" in page.lower():
            raise SearchProviderError(
                "DuckDuckGo served an anti-bot challenge instead of results; configure WormT, "
                "Brave or SearXNG for a provider that will answer reliably"
            )
        raise SearchProviderError("no results parsed from the results page")
    return rows, {}


_PROVIDER_FUNCS = {
    "wormt": _search_wormt,
    "brave": _search_brave,
    "searxng": _search_searxng,
    "duckduckgo": _search_duckduckgo,
}


def _configured_provider_chain(s: Any) -> list[str]:
    """Which providers to try, in order."""
    choice = str(getattr(s, "search_provider", "auto") or "auto").strip().lower()
    if choice in _PROVIDER_FUNCS:
        # An explicit choice still falls back, so a misconfigured key does not leave the agent
        # with no search at all; the response says which provider actually answered.
        return [choice] + [p for p in PROVIDERS if p != choice]
    chain = []
    if str(getattr(s, "wormt_api_url", "") or "").strip():
        chain.append("wormt")
    if str(getattr(s, "brave_search_api_key", "") or "").strip():
        chain.append("brave")
    if str(getattr(s, "searxng_url", "") or "").strip():
        chain.append("searxng")
    chain.append("duckduckgo")
    return chain


# -- page fetch -----------------------------------------------------------------------


def _strip_html_to_text(html: str, max_chars: int) -> str:
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html)
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", t)
    t = re.sub(r"<[^>]+>", " ", t)
    t = html_module.unescape(t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:max_chars]


def fetch_url_text(url: str, *, max_bytes: int = _FETCH_PAGE_BYTES) -> str:
    if not is_safe_public_url(url):
        return ""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
        method="GET",
    )
    # URL checked by is_safe_public_url above.
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="replace")


# -- entry point ----------------------------------------------------------------------


def perform_web_search(
    query: str,
    *,
    max_results: int = 6,
    fetch_primary_excerpt: bool = False,
) -> dict[str, Any]:
    q = (query or "").strip()[:_MAX_QUERY_LEN]
    if not q:
        return {"error": "empty_query", "query": query}
    max_results = max(1, min(int(max_results or 6), 12))

    try:
        s = _settings()
    except Exception as e:  # noqa: BLE001 - a bad settings file must not take search down with it
        logger.warning("web_search: could not load settings (%s); using defaults", e)
        s = object()

    attempts: list[dict[str, str]] = []
    results: list[dict[str, str]] = []
    meta: dict[str, Any] = {}
    used = ""
    for name in _configured_provider_chain(s):
        try:
            results, meta = _PROVIDER_FUNCS[name](q, max_results, s)
        except SearchProviderError as e:
            attempts.append({"provider": name, "error": str(e)[:300]})
            continue
        except Exception as e:  # noqa: BLE001 - one provider's bug must not sink the others
            logger.warning("web_search: provider %s failed: %s", name, e)
            attempts.append({"provider": name, "error": str(e)[:300]})
            continue
        if results:
            used = name
            break
        attempts.append({"provider": name, "error": "no results"})

    if not used:
        return {
            "error": "no_results",
            "query": q,
            "attempts": attempts,
            "hint": (
                "Set WORMT_API_URL (and WORMT_API_KEY), BRAVE_SEARCH_API_KEY or SEARXNG_URL under "
                "File -> Settings for a configured search provider."
            ),
        }

    # Dedupe by URL, preserve rank order.
    seen: set[str] = set()
    uniq: list[dict[str, str]] = []
    for r in results:
        u = r.get("url", "")
        if u in seen:
            continue
        seen.add(u)
        uniq.append(r)
    results = uniq[:max_results]

    out: dict[str, Any] = {
        "query": q,
        "primary_url": results[0]["url"] if results else "",
        "primary_title": results[0].get("title", "") if results else "",
        "primary_snippet": results[0].get("snippet", "") if results else "",
        "results": results,
        "source": used,
        "disclaimer": "Third-party summaries and links; verify before relying on security or legal claims.",
    }
    out.update(meta)
    if attempts:
        out["skipped_providers"] = attempts

    if fetch_primary_excerpt and out["primary_url"] and is_safe_public_url(out["primary_url"]):
        try:
            html = fetch_url_text(out["primary_url"])
            out["fetched_excerpt"] = _strip_html_to_text(html, 6000)
            out["fetched_url"] = out["primary_url"]
        except Exception as e:  # noqa: BLE001 - a page that will not load is reported, not raised
            out["fetch_error"] = str(e)[:500]

    return out
