#!/usr/bin/env bash
# LatchBrowse -> Google Cloud Run (Artifact Registry + Secret Manager + IAM).
# Usage: PROJECT_ID=my-proj REGION=us-central1 ./deployment/deploy_cloudrun.sh
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
REPO="latch-browse"
AR="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}"

gcloud config set project "$PROJECT_ID"
gcloud services enable run.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com cloudbuild.googleapis.com
gcloud artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "$REPO" --repository-format docker --location "$REGION"

# Secret: create once with  printf %s "$KEY" | gcloud secrets create GEMINI_API_KEY --data-file=-
gcloud iam service-accounts describe "latch-guard@${PROJECT_ID}.iam.gserviceaccount.com" >/dev/null 2>&1 || \
  gcloud iam service-accounts create latch-guard --display-name "LatchBrowse guard"
gcloud iam service-accounts describe "latch-app@${PROJECT_ID}.iam.gserviceaccount.com" >/dev/null 2>&1 || \
  gcloud iam service-accounts create latch-app --display-name "LatchBrowse app"
for SA in latch-guard latch-app; do
  gcloud secrets add-iam-policy-binding GEMINI_API_KEY \
    --member "serviceAccount:${SA}@${PROJECT_ID}.iam.gserviceaccount.com" --role roles/secretmanager.secretAccessor >/dev/null
done

# 1) Security Core: private, no unauthenticated access.
gcloud builds submit --tag "${AR}/security-core" --file deployment/Dockerfile.security .
gcloud run deploy latch-guard --image "${AR}/security-core" --region "$REGION" \
  --service-account "latch-guard@${PROJECT_ID}.iam.gserviceaccount.com" \
  --no-allow-unauthenticated --ingress internal-and-cloud-load-balancing \
  --timeout 90 --concurrency 20 --max-instances 3 --memory 512Mi \
  --set-secrets GEMINI_API_KEY=GEMINI_API_KEY:latest
GUARD_URL=$(gcloud run services describe latch-guard --region "$REGION" --format 'value(status.url)')
gcloud run services add-iam-policy-binding latch-guard --region "$REGION" \
  --member "serviceAccount:latch-app@${PROJECT_ID}.iam.gserviceaccount.com" --role roles/run.invoker

# 2) Jac app: public. max-instances=1 keeps the in-memory rate limit a hard limit.
gcloud builds submit --tag "${AR}/app" --file deployment/Dockerfile.app .
gcloud run deploy latch-app --image "${AR}/app" --region "$REGION" \
  --service-account "latch-app@${PROJECT_ID}.iam.gserviceaccount.com" \
  --allow-unauthenticated --max-instances 1 --timeout 300 --memory 1Gi \
  --set-secrets GEMINI_API_KEY=GEMINI_API_KEY:latest \
  --set-env-vars "GUARD_URL=${GUARD_URL},LLM_MODEL=gemini/gemini-2.5-flash,RATE_LIMIT_ENABLED=true,RATE_LIMIT_REQUESTS=20,RATE_LIMIT_WINDOW_SECONDS=3600,TRUSTED_PROXY_HOPS=1,SEARCH_PROVIDER=wikipedia"
gcloud run services describe latch-app --region "$REGION" --format 'value(status.url)'
