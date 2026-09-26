# LatchBrowse functional audit

Reviewed September 26, 2026 against the attached JacHammer build prompt. This is an audit, not a repair. Application source was not changed.

## Why Run secure research appears to do nothing

**Confirmed: the polling callback captures the old session ID.**

`components/ResearchWorkspace.impl.jac:41` assigns `sessionId = res.session_id`, then calls `poll()` and installs an interval calling the same `poll`. Jac compiles the assignment into React's `setSessionId(...)`. That does not update the `sessionId` captured by the current render's functions. On the first run it remains `""`, so `poll` returns at line 17. Subsequent renders do not replace the installed interval callback.

Consequences:

- The backend can accept and execute a research job, but the UI never asks for its status.
- No timeline, content, answer, or backend failure is displayed.
- The button becomes usable again because `starting` becomes false and `session` remains null. Repeated clicks can create additional jobs and consume quota.
- Later clicks can poll a previous session. Timer cleanup has the same stale-state problem: `pollTimer` is React state, and the unmount cleanup captures its initial null value.

Verification: compiled temporary client-context copies of the existing workspace and implementation files with Jac 0.16.7, then exercised the generated handler with React-style state setters and a controlled RPC response. `start_research` returned `ses_test`; both the immediate poll and timer callback produced **zero `get_session` calls**. This was a handler-level reproduction, not a browser test of the hosted preview.

Repair: drive polling from an effect that depends on the accepted session ID; pass the ID explicitly to polling, keep timer ownership in that effect or a ref, and clean up on completion, replacement, and unmount. Handle a missing session and connection failures explicitly.

## Local startup also has two independent blockers

1. `jac start --dev main.jac` fails with E5001 at `main.jac:12` and `main.jac:13`: CSS and npm imports are in server context. The installed compiler requires client context, and the component files similarly need appropriate client treatment. `jac check main.jac` nonetheless reports a pass with unresolved-import/type warnings; that check alone does not establish that the app runs. The repository does not pin the compiler version used by JacHammer.
2. Importing `services.ratelimit` raises `UnboundLocalError` for `_installed` in `install_rate_gate` (`services/ratelimit.jac:120`). The assignment needs a `global` declaration. The rejection branch also assigns `rejected_count` without declaring it global (`:101`), so fixing installation alone leaves a second failure on quota rejection. Generated Python confirms both local-variable assignments.

These findings concern this checkout and installed Jac 0.16.7 / Python 3.14.7. They do not establish which compiler or revision the hosted preview is running.

## Feature verification

| Feature | Result and scope |
| --- | --- |
| Existing automated tests | **18 passed**. These are Python security-core tests, largely using no-key heuristics and mocked model behavior. |
| Research backend | **Passed offline**: controlled search and page responses produced COMPLETE, a validated excerpt answer, one search, one page, three steps, and zero model calls. An empty-result run ended FAILED with an explicit error. |
| Background worker | Ran successfully in the direct offline test. No threading defect was reproduced; request-lifecycle behavior remains unverified. |
| Live web search / Gemini reasoning | **Not verified**. No live model/provider credentials were exercised; offline success does not prove these integrations. Default behavior falls back to Wikipedia and deterministic research when no key exists. |
| Four-layer guard | Real implementation exists. Existing benign/malicious fixture tests, content removal, provenance, typed extraction, page-level disagreement blocking, and simulated model failure tests passed. Additional failures are listed below. |
| Standalone guard HTTP | FastAPI TestClient: `/healthz` returned 200; a benign `/v1/page` request returned 200/PASS. This verifies local handlers, not a deployed network service. |
| Attack Lab | **Seven fixture runs completed through the actual local pipeline**: six attacks SANITIZED, benign control RELEASED; all seven protected fallback validations passed. |
| Protected vs unprotected comparison | Protected heuristic path works. Actual unprotected Gemini behavior and canary leakage were not verified. Without a key, the UI shows raw text and an explanatory error rather than running an agent. |
| IT Review Console backend | Six attack findings persisted. Flagging one produced HUMAN_FLAGGED when findings were reloaded from the temporary store. Actual browser filtering/sorting/refresh was not verified. |
| Console privacy | Stored top-level fields are allow-listed and omit task/intent/session ID. This does not prove no prompt information can appear in free-form model explanations, URLs, or excerpts. |
| Human flagging | Persistence verified. Code inspection shows the guard does not consult the review store, consistent with review-only intent. |
| Capability policy | Direct forbidden `send_email` action was rejected. Enforcement and final validation remain limited as described below. |
| Rate limiting / HTTP 429 | **Broken at module import**, with a second bug in the rejection branch. No successful whole-app 429 verification. |
| Session cost limits | Search/page/step counters exist, but **the total Gemini-call ceiling is not enforced**. |
| Browser UI / accessibility | Not certified: local startup fails before browser QA can run. The button handler was independently reproduced. |
| Containers / Google Cloud | Artifacts exist, but contain deployment defects. No images built or cloud resources deployed during this audit. |

## High-priority defects beyond the button

### Search results can survive a critic rejection

`security_core/pipeline.py:191` blocks the whole search batch only when `not crit.agrees AND det.is_injection`. A critic rejection of a batch that Layer 2 called clean releases the results anyway. **Reproduced:** mocked critic returned disagreement/BLOCK; one search result was still released. Any material critic disagreement must withhold the batch.

### Invalid detector output can be treated as safe

`security_core/detect.py:137` onward supplies permissive defaults instead of validating the required model schema. **Reproduced:** the detector model returned `{}` and a benign page received PASS. This probe used a mocked detector and deterministic critic; it demonstrates missing schema validation, not a live Gemini attack. Also, an injection verdict without valid localized segment IDs can produce SANITIZE without removing the directive. Invalid or unlocalizable security decisions need to fail closed.

### Links bypass content sanitization

`security_core/pipeline.py:141` extracts links from original raw HTML after sanitizing text. The HTML isolation code does not inspect href values. **Reproduced:** a sanitized page retained an arbitrary external href in its SafeArtifact. `services/research.jac` treats artifact links as known/approved retrieval targets. Links need their own validation and provenance/capability enforcement before becoming tool inputs.

### Page-fetch SSRF protections are incomplete

`services/web.jac:101` uses hostname string/regex checks. **Reproduced:** `url_allowed('http://[::1]/')` returned true. DNS resolution to private addresses is not checked. At line 122 redirects are automatically followed, with the final target checked only after the request has happened. Check destinations before every connection/redirect and enforce public-address restrictions. The size limit slices an already downloaded response, so it does not bound download size.

### Gemini-call budget misses most model usage

`services/research.jac` increments `llm_calls` for agent decisions and summaries only. Guard Layer 2/4 calls and their retries are absent from this counter. Summary generation can also run twice without checking the remaining budget. Thus the displayed `gemini N/14` is not total spend and `MAX_GEMINI_CALLS_PER_SESSION` is not a hard ceiling. The remote guard needs a shared/reserved budget contract too.

### Rate limiter trusts arbitrary forwarded headers

`services/ratelimit.jac:29` uses X-Forwarded-For whenever it is present, including direct local/non-proxied requests; it does not establish a trusted proxy first. Its exact-path gate also needs integration tests against actual routes and alternate accepted URL forms. Fixing the two scope bugs is necessary but insufficient to verify wallet protection.

### Validation/status presentation overstates assurance

- Final answer relevance is only a one-word overlap check (`services/policy.jac`). It validates the separate cited-sources list, not every URL or assertion in answer text. Empty citations can pass. This is not substantive answer-quality validation.
- No-key Attack Lab validation appends the user goal to the answer being checked, guaranteeing topic overlap, and does not withhold fallback output when validation fails (`services/attacklab.jac`).
- `guard_status`/`guard_mode` inspect local key/configuration rather than probing the configured remote guard. A configured key is not evidence that Gemini or the remote guard is healthy.
- The review console fetches on entry/manual refresh; it is not a live findings stream.
- The content viewer shows surviving segments even when a critic blocks the whole artifact, so the sanitized view is not necessarily the exact context released to the agent.

## Deployment findings

`deployment/deploy_cloudrun.sh:26` and `:37` use `gcloud builds submit --file`, which is not a supported flag in the documented command. Use a Cloud Build configuration that invokes Docker with the chosen Dockerfile. [Google command reference](https://docs.cloud.google.com/sdk/gcloud/reference/builds/submit).

The guard uses `internal-and-cloud-load-balancing` ingress, but the script does not configure the app's required internal network route. IAM permission alone does not provide that route. [Google ingress requirements](https://docs.cloud.google.com/run/docs/securing/ingress).

The app runs research in background daemon threads after the start request returns; Cloud Run CPU allocation and job lifetime need explicit design/verification. Findings/reviews use ephemeral local storage, with no persistence volume provisioned by the script. Compiler and most Python dependencies are unpinned. These prevent calling deployment verified or reproducible.

## Recommended repair order

1. Correct polling and timer ownership; add a handler/browser regression test proving the new session is polled and terminal results are displayed.
2. Pin a compatible Jac environment; repair client contexts and both rate-gate global declarations; verify startup and 429 responses before external calls.
3. Enforce strict detector schemas, unconditional critic-disagreement blocking, checked links, and pre-request SSRF protections.
4. Count/reserve all model calls and retries against a real session budget.
5. Verify live Gemini, search, remote guard, and browser flows; harden validation and status reporting.
6. Repair and exercise container/Cloud Run deployment, including background execution and persistence.

The repository has substantial functional pieces, but it does **not** currently meet the attached prompt's end-to-end, fail-closed, hard-budget, or deployment acceptance criteria.
