"""Shared key-value state for sessions, findings and rate-limit counters.

Vercel runs the API as short-lived instances that share no memory, so when
Upstash Redis REST credentials are present (the Vercel Marketplace Upstash
integration sets KV_REST_API_URL / KV_REST_API_TOKEN) every instance reads and
writes the same store. Without them this falls back to a per-process dict,
which is all a single `jac start` server needs.
"""

import os;
import time;
import threading;
import httpx;

glob _mem: dict = {},
     _mlock: threading.Lock = threading.Lock();

def _rest() -> tuple[str, str] {
    url = os.environ.get("KV_REST_API_URL", "") or os.environ.get("UPSTASH_REDIS_REST_URL", "");
    token = os.environ.get("KV_REST_API_TOKEN", "") or os.environ.get("UPSTASH_REDIS_REST_TOKEN", "");
    return (url.rstrip("/"), token);
}

"""True when state is shared across instances (Redis configured)."""
def shared_store() -> bool {
    (url, token) = _rest();
    return bool(url and token);
}

"""One Redis command over the Upstash REST API."""
def _cmd(args: list) -> any {
    (url, token) = _rest();
    r = httpx.post(url, json=[str(a) for a in args], headers={"Authorization": "Bearer " + token}, timeout=8.0);
    body: dict = {};
    try { body = r.json() as dict; } except Exception { r.raise_for_status(); }
    if "error" in body { raise RuntimeError("store error: " + str(body["error"])[:200]); }
    r.raise_for_status();
    return body.get("result");
}

# Caller holds _mlock. Entries are (value, expires_at); expires_at 0 = never.
def _live(key: str) -> any {
    item = _mem.get(key);
    if item is None { return None; }
    if item[1] and item[1] < time.time() {
        del _mem[key];
        return None;
    }
    return item[0];
}

def kv_get(key: str) -> str | None {
    if shared_store() {
        v = _cmd(["GET", key]);
        return None if v is None else str(v);
    }
    with _mlock { return _live(key) as str | None; }
}

def kv_put(key: str, value: str, ttl: int) -> None {
    if shared_store() {
        _cmd(["SET", key, value, "EX", ttl]);
        return;
    }
    with _mlock { _mem[key] = (value, time.time() + ttl); }
}

"""Set key only if absent. True when this caller won it (at-most-once work)."""
def kv_claim(key: str, ttl: int) -> bool {
    if shared_store() {
        return _cmd(["SET", key, "1", "NX", "EX", ttl]) == "OK";
    }
    with _mlock {
        if _live(key) is not None { return False; }
        _mem[key] = ("1", time.time() + ttl);
        return True;
    }
}

"""Set key only if absent, then return its value: every instance ends up
agreeing on the first writer's value."""
def kv_setdefault(key: str, value: str, ttl: int) -> str {
    if shared_store() {
        _cmd(["SET", key, value, "NX", "EX", ttl]);
        current = _cmd(["GET", key]);
        return value if current is None else str(current);
    }
    with _mlock {
        current = _live(key);
        if current is None {
            _mem[key] = (value, time.time() + ttl);
            return value;
        }
        return current as str;
    }
}

"""Increment a counter whose window starts at its first hit and lasts ttl
seconds. Returns (count, seconds_left_in_window)."""
def kv_incr(key: str, ttl: int) -> tuple[int, int] {
    if shared_store() {
        # SET NX EX creates the window with its expiry before INCR, so a key
        # can never be left without a TTL.
        _cmd(["SET", key, "0", "NX", "EX", ttl]);
        n = int(_cmd(["INCR", key]));
        left = int(_cmd(["TTL", key]));
        return (n, left if left > 0 else ttl);
    }
    with _mlock {
        now = time.time();
        item = _mem.get(key);
        if item is None or item[1] < now { item = (0, now + ttl); }
        _mem[key] = (int(item[0]) + 1, item[1]);
        return (int(item[0]) + 1, int(item[1] - now) + 1);
    }
}

# List / hash helpers used by the findings store in shared mode only.
def kv_counter(key: str) -> int {
    return int(_cmd(["INCR", key]));
}

def kv_append(key: str, value: str, keep: int) -> None {
    _cmd(["RPUSH", key, value]);
    _cmd(["LTRIM", key, -keep, -1]);
}

def kv_list(key: str) -> list[str] {
    return [str(v) for v in (_cmd(["LRANGE", key, 0, -1]) or [])];
}

def kv_hset(key: str, field: str, value: str) -> None {
    _cmd(["HSET", key, field, value]);
}

def kv_hgetall(key: str) -> dict[str, str] {
    flat: list = (_cmd(["HGETALL", key]) or []) as list;
    return {str(flat[i]): str(flat[i + 1]) for i in range(0, len(flat) - 1, 2)};
}
