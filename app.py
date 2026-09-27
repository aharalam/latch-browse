"""Vercel entrypoint: the LatchBrowse server functions as one FastAPI app.

`jac start main.jac` stays the local server. On Vercel there is no long-running
process, so this module exposes the same public functions at the same
`/function/<name>` paths, with the same response envelope, for Vercel's Python
runtime. The UI is the static build in ui/ (see scripts/vercel-build.sh),
mounted below and served from the function bundle (Vercel may also promote
the mount to its CDN).
"""

import asyncio
import inspect
import logging
import os

import jaclang  # noqa: F401  (registers the .jac import hook)
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from jaclang.runtimelib.serializer import Serializer

# Importing ratelimit wraps every FastAPI app in the RateGate middleware, so it
# must happen before the app below handles its first request.
import services.ratelimit  # noqa: F401
from services.attacklab import list_fixtures, run_attack_fixture
from services.findings import flag_finding, list_findings
from services.research import get_session, guard_status, run_session, start_research
from services.store import shared_store

log = logging.getLogger("latch")

# Only these are reachable over HTTP; internal helpers are not.
PUBLIC = {
    fn.__name__: fn
    for fn in (start_research, run_session, get_session, guard_status,
               list_findings, flag_finding, list_fixtures, run_attack_fixture)
}

app = FastAPI(title="LatchBrowse", docs_url=None, redoc_url=None, openapi_url=None)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"ok": False, "type": "error", "data": None, "error": {"message": message}}, status_code=status)


@app.post("/function/{name}")
async def call_function(name: str, request: Request):
    fn = PUBLIC.get(name)
    if fn is None:
        return _error(404, f"Unknown function '{name}'")
    if os.environ.get("VERCEL") == "1" and not shared_store():
        # Without a shared store each instance would keep its own sessions,
        # findings and rate limits: fail clearly instead of intermittently.
        return _error(503, "Shared store not configured: connect Upstash Redis to this Vercel project and redeploy.")
    try:
        body = await request.json() if await request.body() else {}
    except ValueError:
        return _error(400, "Request body must be JSON")
    if not isinstance(body, dict):
        return _error(400, "Request body must be a JSON object")
    params = inspect.signature(fn).parameters
    args = {k: v for k, v in body.items() if k in params}
    try:
        # Sync Jac functions run in a worker thread so a long research run
        # never blocks polls served by the same instance.
        result = await asyncio.to_thread(fn, **args)
    except TypeError as exc:
        return _error(422, f"Bad arguments for '{name}': {exc}")
    except Exception:
        log.exception("function %s failed", name)
        return _error(500, f"'{name}' failed")
    return {"ok": True, "type": "response", "data": {"result": Serializer.serialize(result, api_mode=True), "reports": []}, "error": None}


@app.post("/cl/__error__")
async def client_error(request: Request):
    # The Jac client runtime reports browser errors here; keep them in the logs.
    log.warning("client error: %s", (await request.body())[:2000].decode("utf-8", "replace"))
    return Response(status_code=204)


@app.get("/healthz")
def healthz():
    return {"ok": True}


# The UI: /, /console/ and /lab/ are index.html files built by
# scripts/vercel-build.sh into ui/ (not public/: Vercel neither bundles nor
# publishes a public/ that only exists after the build). Mounted last so the
# API routes above take priority.
UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
if os.path.isdir(UI_DIR):
    app.mount("/", StaticFiles(directory=UI_DIR, html=True), name="ui")
