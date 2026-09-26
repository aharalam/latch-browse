"""FastAPI wrapper for deploying the Security Core as its own Cloud Run service.

Deploy with --no-allow-unauthenticated; the Jac app calls it with a Google
identity token (service-to-service IAM). An optional shared secret
(GUARD_SHARED_SECRET) adds a second check for local runs.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .pipeline import guard_status, process_page, process_search_results

app = FastAPI(title="LatchBrowse Security Core", docs_url=None, redoc_url=None)
MAX_BYTES = int(os.environ.get("GUARD_MAX_BYTES", "600000"))


class Intent(BaseModel):
    goal: str = Field(max_length=600)
    allowed: list[str] = []
    forbidden: list[str] = []


class PageReq(BaseModel):
    url: str = Field(max_length=2000)
    raw: str
    is_html: bool = True
    intent: Intent


class SearchReq(BaseModel):
    results: list[dict] = Field(max_length=20)
    intent: Intent


def _auth(secret: str | None) -> None:
    expected = os.environ.get("GUARD_SHARED_SECRET")
    if expected and secret != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, **guard_status()}


@app.post("/v1/page")
def page(req: PageReq, x_guard_secret: str | None = Header(default=None)) -> dict:
    _auth(x_guard_secret)
    if len(req.raw.encode("utf-8", "ignore")) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="content too large")
    return process_page(req.raw, req.url, req.intent.model_dump(), is_html=req.is_html)


@app.post("/v1/search")
def search(req: SearchReq, x_guard_secret: str | None = Header(default=None)) -> dict:
    _auth(x_guard_secret)
    return process_search_results(req.results, req.intent.model_dump())
