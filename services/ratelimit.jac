"""Hackathon cost-protection gate (NOT part of the prompt-injection defense).

A per-client-IP rolling-window limiter installed as the OUTERMOST ASGI layer,
so a rejected request returns HTTP 429 before any Jac endpoint, agent, model,
search, retrieval or guard code runs.

Client IP: Cloud Run's front end APPENDS the real peer address to
X-Forwarded-For, so client-supplied entries come first. We take the entry
TRUSTED_PROXY_HOPS from the right and never the leftmost (spoofable) one.
State is in-memory: deploy the Jac service with --max-instances=1 so the
limit is a hard limit (see README for the Memorystore upgrade path).

On Vercel (VERCEL=1) the client IP is x-vercel-forwarded-for, which Vercel's
edge overwrites so clients cannot spoof it, and counters live in the shared
store (services/store.jac) because instances share no memory. There the
window is fixed from a client's first request rather than rolling.
"""

import json;
import time;
import hashlib;
import threading;
import os;
import secrets;
import ipaddress;
import from fastapi { FastAPI }
import from services.config { get_budgets }
import from services.store { shared_store, kv_incr, kv_setdefault }

# Paths that start expensive work. Everything else (UI, polling, console) is free.
glob GATED_PATHS: list[str] = ["/function/start_research", "/function/run_attack_fixture"];

glob _hits: dict[str, list[float]] = {},
     _lock: threading.Lock = threading.Lock(),
     _installed: bool = False,
     rejected_count: int = 0,
     _salt: str = secrets.token_hex(16),
     _shared_salt: str = "";

def resolve_client_ip(headers: dict, peer: str) -> str {
    if os.environ.get("VERCEL") == "1" {
        vercel_ip = str(headers.get("x-vercel-forwarded-for", "")).split(",")[0].strip();
        if vercel_ip { return vercel_ip; }
    }
    xff = headers.get("x-forwarded-for", "");
    trusted = False;
    try {
        address = ipaddress.ip_address(peer);
        for cidr in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(",") {
            if cidr.strip() and address in ipaddress.ip_network(cidr.strip()) { trusted = True; }
        }
    } except ValueError { trusted = False; }
    if xff and trusted {
        parts = [p.strip() for p in xff.split(",") if p.strip()];
        hops = get_budgets().trusted_proxy_hops;
        if len(parts) >= hops {
            try { return str(ipaddress.ip_address(parts[len(parts) - hops])); }
            except ValueError { return peer or "unknown"; }
        }
    }
    return peer or "unknown";
}

def _key(ip: str) -> str {
    # Only a salted hash is kept; raw IPs are never logged, shown or stored.
    return hashlib.sha256((_salt_value() + ip).encode("utf-8")).hexdigest()[:20];
}

"""Instances sharing a store must hash a client IP to the same key, so they
share one salt (first writer wins) instead of each generating its own."""
def _salt_value() -> str {
    global _shared_salt;
    if not shared_store() { return _salt; }
    if not _shared_salt {
        _shared_salt = kv_setdefault("latch:rl:salt", secrets.token_hex(16), 30 * 86400);
    }
    return _shared_salt;
}

"""Consume one research-request slot. Returns (allowed, retry_after_seconds)."""
def check_rate_limit(ip: str) -> tuple[bool, int] {
    cfg = get_budgets();
    if not cfg.rate_limit_enabled {
        return (True, 0);
    }
    key = _key(ip);
    if shared_store() {
        (count, left) = kv_incr("latch:rl:" + key, cfg.rate_limit_window_seconds);
        return (True, 0) if count <= cfg.rate_limit_requests else (False, left);
    }
    now = time.time();
    window = float(cfg.rate_limit_window_seconds);
    with _lock {
        recent = [t for t in _hits.get(key, []) if now - t < window];
        if len(recent) >= cfg.rate_limit_requests {
            _hits[key] = recent;
            retry = int(window - (now - recent[0])) + 1;
            return (False, retry);
        }
        recent.append(now);
        _hits[key] = recent;
        return (True, 0);
    }
}

def reset_rate_limits() -> None {
    with _lock {
        _hits.clear();
    }
}

def _reject_body(retry: int) -> bytes {
    return json.dumps({
        "ok": False,
        "type": "error",
        "data": None,
        "error": {
            "code": "RATE_LIMITED",
            "message": "Request limit reached. This demo is temporarily limiting research requests to protect hackathon API resources. Please try again later."
        },
        "meta": {"extra": {"http_status": 429, "retry_after": retry}}
    }).encode("utf-8");
}

obj RateGate {
    has app: any;

    async def __call__(scope: dict, receive: any, send: any) -> None {
        global rejected_count;
        path = "/" + "/".join([p for p in scope.get("path", "").split("/") if p]);
        if scope.get("type") == "http" and scope.get("method") != "OPTIONS" and path in GATED_PATHS {
            headers: dict = {};
            for pair in scope.get("headers", []) {
                headers[pair[0].decode("latin-1").lower()] = pair[1].decode("latin-1");
            }
            client = scope.get("client");
            peer = client[0] if client else "";
            (ok, retry) = check_rate_limit(resolve_client_ip(headers, peer));
            if not ok {
                rejected_count += 1;
                await send({
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"retry-after", str(retry).encode("latin-1"))
                    ]
                });
                await send({"type": "http.response.body", "body": _reject_body(retry)});
                return;
            }
        }
        await self.app(scope, receive, send);
    }
}

"""Wrap FastAPI's middleware stack with RateGate so it runs outermost."""
def install_rate_gate() -> None {
    global _installed;
    if _installed {
        return;
    }
    _installed = True;
    original: any = FastAPI.build_middleware_stack;
    def patched(app_self: any) -> any {
        inner: any = original(app_self);
        return RateGate(app=inner);
    }
    FastAPI.build_middleware_stack = patched;
}

with entry {
    install_rate_gate();
}
