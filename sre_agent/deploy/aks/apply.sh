#!/usr/bin/env bash
#
# Turnkey apply for the SRE Agent on AKS. Substitutes the <TOKEN> placeholders
# from deploy.env into every manifest and applies them in dependency order,
# then runs smoke checks.
#
#   cp deploy.env.example deploy.env && $EDITOR deploy.env   # fill in values
#   ./apply.sh render        # print the rendered manifests, apply nothing
#   ./apply.sh dry-run       # server-side --dry-run, apply nothing
#   ./apply.sh apply         # apply for real (default), then smoke-check
#
# Prereqs: kubectl pointed at the cluster (`az aks get-credentials ...`), and
# the one-time cluster setup in README (Workload Identity federation, KEDA,
# Key Vault CSI addon, ingress controller). Secrets must already be in Key Vault.
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-apply}"
ENV_FILE="${SRE_ENV_FILE:-./deploy.env}"
NS="sre-agent"

# Manifests in dependency order (namespace first; ingress last).
MANIFESTS=(
  namespace serviceaccount configmap secretproviderclass data-pvc
  worker-deployment worker-scaledobject api-deployment oauth2-proxy
  networkpolicy maintenance-cronjob ingress
)

REQUIRED_VARS=(
  ACR_LOGIN_SERVER IMAGE_TAG MANAGED_IDENTITY_CLIENT_ID
  KEYVAULT_NAME TENANT_ID HOST AOAI_RESOURCE
)

die() { echo "error: $*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "$ENV_FILE not found (cp deploy.env.example deploy.env)"
# shellcheck disable=SC1090
source "$ENV_FILE"
for v in "${REQUIRED_VARS[@]}"; do
  [ -n "${!v:-}" ] || die "$v is not set in $ENV_FILE"
done

render() {  # render one manifest to stdout with placeholders substituted
  sed -e "s|<ACR_LOGIN_SERVER>|${ACR_LOGIN_SERVER}|g" \
      -e "s|<TAG>|${IMAGE_TAG}|g" \
      -e "s|<MANAGED_IDENTITY_CLIENT_ID>|${MANAGED_IDENTITY_CLIENT_ID}|g" \
      -e "s|<KEYVAULT_NAME>|${KEYVAULT_NAME}|g" \
      -e "s|<TENANT_ID>|${TENANT_ID}|g" \
      -e "s|<HOST>|${HOST}|g" \
      -e "s|<AOAI_RESOURCE>|${AOAI_RESOURCE}|g" \
      "$1.yaml"
}

render_all() { for m in "${MANIFESTS[@]}"; do render "$m"; echo "---"; done; }

case "$MODE" in
  render)
    render_all
    exit 0
    ;;
  dry-run)
    render_all | kubectl apply --dry-run=server -f -
    exit 0
    ;;
  apply) ;;
  *) die "unknown mode '$MODE' (use: render | dry-run | apply)" ;;
esac

echo ">> applying manifests to namespace/$NS"
for m in "${MANIFESTS[@]}"; do
  echo "   - $m"
  render "$m" | kubectl apply -f -
done

echo ">> waiting for rollouts"
kubectl -n "$NS" rollout status deploy/oauth2-proxy       --timeout=180s
kubectl -n "$NS" rollout status deploy/sre-agent-api      --timeout=180s
kubectl -n "$NS" rollout status deploy/sre-agent-worker   --timeout=180s

echo ">> smoke checks"
# Key Vault CSI sync produced the env secret.
kubectl -n "$NS" get secret sre-agent-secrets >/dev/null \
  && echo "   ok: sre-agent-secrets synced from Key Vault"
# KEDA is managing the worker.
kubectl -n "$NS" get scaledobject sre-agent-worker >/dev/null \
  && echo "   ok: KEDA ScaledObject present"
# API liveness + DB readiness via a short-lived port-forward.
kubectl -n "$NS" port-forward svc/sre-agent-api 18080:8080 >/dev/null 2>&1 &
pf_pid=$!
trap 'kill "$pf_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 15); do
  curl -sf http://localhost:18080/healthz >/dev/null 2>&1 && break; sleep 1
done
curl -sf http://localhost:18080/healthz >/dev/null && echo "   ok: /healthz"
ready="$(curl -sf http://localhost:18080/readyz || true)"
echo "   readyz: ${ready:-<unreachable>}"
case "$ready" in *'"database":true'*) echo "   ok: database reachable" ;;
  *) echo "   WARN: database not reachable — check SRE_AGENT_DATABASE_URL secret" ;;
esac

echo ">> done. Browse https://${HOST} (Entra login via oauth2-proxy)."
