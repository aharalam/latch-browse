# Deploying LatchBrowse to Vercel

One Vercel project runs the whole app: the three UI pages, the API with its
middleware, the research agent and the four-layer security core. Upstash Redis,
added through the Vercel Marketplace, holds the state that has to be shared
between Vercel's short-lived instances.

## What runs where

| Part | On Vercel | Source |
|---|---|---|
| Research workspace (`/`), IT Review Console (`/console`), Attack Lab (`/lab`) | Static files built into `ui/` at deploy time and served by the same function (`app.py` mounts them) | `components/`, `scripts/vercel-build.sh` |
| API (`/function/*`) | One Python Vercel Function | `app.py` |
| Rate gate middleware (HTTP 429) | Inside the function, in front of every endpoint | `services/ratelimit.jac` |
| Capability policy, final validator | Inside the function | `services/policy.jac` |
| Research agent + summary agent (Gemini) | Inside the function | `services/research.jac`, `services/agents.jac` |
| Security core, layers 1–4 | Inside the function (in-process guard) | `security_core/` |
| Sessions, findings, reviews, rate-limit counters | Upstash Redis | `services/store.jac` |

Not deployed: the standalone guard service (`security_core/server.py`, used only
when `GUARD_URL` is set) and the Docker/Cloud Run files in `deployment/`. On
Vercel the same security-core code runs in-process, as it does locally.

## How it differs from `jac start`

Vercel keeps nothing in memory between requests, and work can't keep running
after a response has been sent. So:

- **Research runs as its own request.** `start_research` only registers the
  session. The page then calls `run_session`, which runs the agent to the end
  inside that request (at most 300 s on the Hobby plan). Each timeline event is
  written to Redis, so the page's polling (`get_session`) can hit any instance.
- **Findings and reviews** live in Redis instead of JSON files (Vercel's disk is
  read-only and not shared). The newest 500 findings are kept.
- **The rate limit** is counted in Redis per client IP. The IP comes from Vercel's
  `x-vercel-forwarded-for` header, which clients can't forge. The window is
  fixed: it starts at a client's first request and doesn't roll.

Local development with `jac start main.jac` is unchanged apart from the first
point, and it uses the same code paths.

## Before you start

- The repo pushed to GitHub, GitLab or Bitbucket.
- A Vercel account (vercel.com). The free Hobby plan works; see the limits below.
- A Gemini API key from https://aistudio.google.com/apikey.

## Steps

### 1. Import the project
1. In the Vercel dashboard, choose **Add New → Project** and import the repository.
2. Leave **Root Directory** as the repository root. Vercel should detect
   **FastAPI** from `app.py` and `requirements.txt`. `vercel.json` supplies the
   build command and function settings, so leave those fields at their defaults.
3. Before clicking **Deploy**, open **Environment Variables** and add:

   | Name | Value | Required |
   |---|---|---|
   | `GEMINI_API_KEY` | your key | Yes. Without it the app runs in the weaker no-key mode. |
   | `LLM_MODEL` | `gemini/gemini-2.5-flash` | No (this is the default) |
   | `SEARCH_PROVIDER` / `BRAVE_API_KEY` / `GOOGLE_CSE_KEY` / `GOOGLE_CSE_ID` | see `.env.example` | No (Wikipedia search is the default) |
   | `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW_SECONDS`, `MAX_*` budgets | see `.env.example` | No (defaults: 20/hour; 3 searches, 4 pages, 8 steps, 14 Gemini calls per task) |

   Don't set `GUARD_URL`, `LATCH_DATA_DIR` or the `TRUSTED_PROXY_*` variables on Vercel.
   Don't add a variable with an empty value; leave it out instead. (Empty
   `LLM_MODEL` / `GUARD_MODEL` are now treated as the default, but it's still the
   clearest setup.)

4. Click **Deploy**. The first deploy will build, but the app will answer every
   request with *"Shared store not configured"* until you finish step 2. That's
   deliberate.

### 2. Connect Upstash Redis
1. In the project, open the **Storage** tab (or **Integrations → Marketplace**),
   choose **Upstash → Redis**, and create a database. Pick the region closest to
   the function's region. Vercel functions default to Washington, D.C. (`iad1`),
   so choose a US East region.
2. Connect it to the project for all environments. This adds
   `KV_REST_API_URL` and `KV_REST_API_TOKEN` to the project's environment
   variables. (`UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` also work.)
3. Redeploy (**Deployments → ⋯ → Redeploy**) so the function picks up the new
   variables.

### 3. Check the deployment
- **Research (`/`)**: the status in the top right reads **GEMINI CONFIGURED /
  WIKIPEDIA**. Run an example task: the timeline fills in live and a validated
  answer appears.
- **Attack Lab (`/lab`)**: run a fixture. The protected side shows SANITIZED.
- **IT Review Console (`/console`)**: the finding from the lab appears. Flag it,
  then reload the page; it should stay flagged.
- **Rate limit**: the 21st research or lab run from one IP within an hour gets
  the *"Request limit reached"* banner.
- **Logs**: *Project → Logs* shows function output, including browser errors
  reported to `/cl/__error__`.

After that, every push to the production branch deploys automatically. Other
branches get preview deployments; Vercel puts those behind login by default.

## Limits to know about

- **300-second run limit (Hobby).** A research task must finish within one
  function invocation. The default budgets normally take well under that. If a
  run is cut off, the page reports it as failed after about 5½ minutes. On Pro
  you can raise `maxDuration` in `vercel.json` (up to 800).
- **Cold starts.** The first request after a quiet period loads Jac, litellm and
  the security core, which takes a few seconds.
- **Function size.** The dependencies are about 390 MB, under Vercel's 500 MB
  Python limit. If a build ever reports the bundle as too large, new projects
  can use Large Functions.
- **Usage.** Each research task makes on the order of 100 Redis commands
  (event writes plus polls). Check the Upstash free-tier limits and the Vercel
  Hobby terms (Hobby is for non-commercial use) against your expected traffic.
- **Retention.** Sessions expire from Redis after 1 hour. Findings keep the
  newest 500.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Shared store not configured" | Upstash isn't connected to this environment, or you haven't redeployed since connecting it. |
| Status shows "degraded guard (no key)" | `GEMINI_API_KEY` is missing for this environment (Production vs Preview). Add it and redeploy. |
| Every page shows GUARD UNAVAILABLE / BLOCKED | The key is set but Gemini calls fail (invalid key, quota). The guard blocks content on purpose when that happens. Check the function logs. |
| Research ends with "stopped before finishing" | The run hit the function time limit. Lower `MAX_AGENT_STEPS` / `MAX_PAGES_PER_SESSION`, or raise `maxDuration` on Pro. |
| `{"detail":"Not Found"}` on `/`, `/console` or `/lab` | The build step didn't produce `ui/index.html` (plus `ui/console/` and `ui/lab/`). Check the build log for `scripts/vercel-build.sh`. Don't rename `ui/` to `public/`: Vercel neither bundles nor publishes a `public/` folder that is created during the build. |

## How this was tested

No real Vercel project was available. `vercel build` (Vercel CLI 60) was run locally to check the generated routing and function bundle, and the runtime was emulated:
- `app.py` ran in a fresh install of `requirements.txt` only (what Vercel installs).
- It ran from a read-only copy of the repo, with 3 worker processes that share
  no memory.
- A fake Upstash REST server stood in for Redis.
- A front server set `x-vercel-forwarded-for` the way Vercel's edge does.

All three pages, cross-instance polling, at-most-once runs, findings and flags,
and the shared rate limit (including a forged-header attempt) worked in the
browser. `tests/test_vercel_mode.py` covers the same paths offline. The actual
Vercel build and runtime still need a first real deploy to confirm.
