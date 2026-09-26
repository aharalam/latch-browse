"""Search + retrieval providers. Returns RAW untrusted data that must only be
handed to the guard (services/guard.jac). Never imported by the agents.

Search provider (SEARCH_PROVIDER): "brave" (BRAVE_API_KEY), "google"
(GOOGLE_CSE_KEY + GOOGLE_CSE_ID), or "wikipedia" (keyless fallback, default
when no key is present).
"""

import os;
import re;
import html;
import httpx;
import socket;
import ipaddress;
import from urllib.parse { urlparse, urljoin, urlunparse }
import from services.config { get_budgets }

glob UA: str = "LatchBrowse/0.1 (+research agent; hackathon demo)";
glob MAX_PAGE_BYTES: int = 400000;

obj RawResult {
    has title: str,
        url: str,
        snippet: str;
}

def _strip_tags(s: str) -> str {
    return html.unescape(re.sub(r"<[^>]+>", "", s or ""));
}

def _brave(query: str) -> list[RawResult] {
    r = httpx.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": 6},
        headers={"X-Subscription-Token": os.environ.get("BRAVE_API_KEY", ""), "Accept": "application/json"},
        timeout=10.0
    );
    r.raise_for_status();
    out: list[RawResult] = [];
    for it in (r.json().get("web", {}) or {}).get("results", [])[:6] {
        out.append(RawResult(title=str(it.get("title", "")), url=str(it.get("url", "")), snippet=_strip_tags(str(it.get("description", "")))));
    }
    return out;
}

def _google(query: str) -> list[RawResult] {
    r = httpx.get(
        "https://www.googleapis.com/customsearch/v1",
        params={"q": query, "key": os.environ.get("GOOGLE_CSE_KEY", ""), "cx": os.environ.get("GOOGLE_CSE_ID", ""), "num": 6},
        timeout=10.0
    );
    r.raise_for_status();
    out: list[RawResult] = [];
    for it in r.json().get("items", [])[:6] {
        out.append(RawResult(title=str(it.get("title", "")), url=str(it.get("link", "")), snippet=str(it.get("snippet", ""))));
    }
    return out;
}

def _wikipedia(query: str) -> list[RawResult] {
    r = httpx.get(
        "https://en.wikipedia.org/w/api.php",
        params={"action": "query", "list": "search", "srsearch": query, "format": "json", "srlimit": 6},
        headers={"User-Agent": UA},
        timeout=10.0
    );
    r.raise_for_status();
    out: list[RawResult] = [];
    for it in r.json().get("query", {}).get("search", [])[:6] {
        title = str(it.get("title", ""));
        out.append(RawResult(
            title=title,
            url="https://en.wikipedia.org/wiki/" + title.replace(" ", "_"),
            snippet=_strip_tags(str(it.get("snippet", "")))
        ));
    }
    return out;
}

def provider_name() -> str {
    p = get_budgets().search_provider;
    if p == "brave" and os.environ.get("BRAVE_API_KEY", "") {
        return "brave";
    }
    if p == "google" and os.environ.get("GOOGLE_CSE_KEY", "") {
        return "google";
    }
    return "wikipedia";
}

def raw_search(query: str) -> list[RawResult] {
    p = provider_name();
    if p == "brave" {
        return _brave(query);
    }
    if p == "google" {
        return _google(query);
    }
    return _wikipedia(query);
}

"""Reject non-http(s), local and private targets (basic SSRF protection)."""
def url_allowed(url: str) -> bool {
    try {
        u = urlparse(url);
    } except Exception {
        return False;
    }
    if u.scheme not in ["http", "https"] or not u.hostname {
        return False;
    }
    host = u.hostname.lower();
    if u.username or u.password { return False; }
    try {
        if u.port is not None and u.port not in [80, 443] { return False; }
        ip = ipaddress.ip_address(host);
        return bool(ip.is_global and not ip.is_multicast);
    } except ValueError {
        if ":" in host { return False; }
    }
    if host in ["localhost", "metadata.google.internal"] or host.endswith(".internal") or host.endswith(".local") {
        return False;
    }
    if re.match(r"^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)", host) {
        return False;
    }
    return True;
}

"""Fetch raw HTML. No scripts executed, no sub-resources fetched."""
def raw_fetch(url: str) -> str {
    current = url;
    with httpx.Client(follow_redirects=False, timeout=12.0, trust_env=False) as client {
        for hop in range(6) {
            if not url_allowed(current) { raise ValueError("disallowed page URL"); }
            parsed = urlparse(current);
            host = str(parsed.hostname);
            port = parsed.port or (443 if parsed.scheme == "https" else 80);
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM);
            if not addresses { raise ValueError("host has no addresses"); }
            for address in addresses {
                ip = ipaddress.ip_address(address[4][0]);
                if not ip.is_global or ip.is_multicast { raise ValueError("host resolves to a non-public address"); }
            }
            # Pin the connection to a checked IP; preserve Host and TLS SNI.
            # This prevents a second DNS lookup from rebinding to a private IP.
            target = str(addresses[0][4][0]);
            if ":" in target { target = "[" + target + "]"; }
            target = target + ":" + str(port);
            pinned = urlunparse((parsed.scheme, target, parsed.path, parsed.params, parsed.query, ""));
            with client.stream("GET", pinned, headers={"User-Agent": UA, "Host": parsed.netloc}, extensions={"sni_hostname": host}) as response {
                if response.status_code in [301, 302, 303, 307, 308] {
                    location = response.headers.get("location", "");
                    if not location { raise ValueError("redirect missing location"); }
                    current = urljoin(current, location);
                    continue;
                }
                response.raise_for_status();
                ctype = str(response.headers.get("content-type", "")).lower();
                if "html" not in ctype and not ctype.startswith("text/") { raise ValueError("unsupported content type"); }
                body = bytearray();
                for chunk in response.iter_bytes(chunk_size=8192) {
                    if len(body) + len(chunk) > MAX_PAGE_BYTES { raise ValueError("page exceeds byte limit"); }
                    body.extend(chunk);
                }
                return body.decode(response.encoding or "utf-8", errors="replace");
            }
        }
    }
    raise ValueError("too many redirects");
}
