# Deploying the SRE Agent on AKS

This is the Kubernetes deployment — an alternative to the Azure Functions /
App Service surface in [`../README.md`](../README.md). Same application code,
different platform. Use this when your org standardizes on AKS.

## Why it maps cleanly

The worker was already a plain long-running process (the Service Bus
**listener**, `python -m sre_agent.main listen`) and the API is plain uvicorn,
so almost nothing in the app changes:

| Concern | Functions / App Service | AKS |
| --- | --- | --- |
| Worker | Functions Service Bus trigger | listener `Deployment` |
| Worker autoscale | Functions runtime | **KEDA** Service Bus scaler |
| Timer sweep | Functions timer | listener's inline sweep + a `CronJob` |
| Web API | App Service (uvicorn) | `Deployment` + `Service` + `Ingress` |
| Auth | Easy Auth injects `X-MS-CLIENT-PRINCIPAL` | **oauth2-proxy** forwards the Entra token → the API's bearer auth path |
| Secrets | App settings / Key Vault refs | Key Vault **CSI** + Workload Identity |
| Shared FS | Azure Files mount | Azure Files **PVC** (ReadWriteMany) |
| State | Postgres | Postgres (unchanged) |

Two bonuses over Functions: KEDA gives event-driven autoscaling (the worker
can scale with subscription depth), and there's **no execution-time ceiling**
for the long LLM investigations.

## The one real change: auth

Easy Auth is App-Service-only. On AKS, **oauth2-proxy** (reverse-proxy mode)
terminates the Entra OIDC login and forwards the ID token as
`Authorization: Bearer`. The API reads the SAME `roles` + identity claims it
read from Easy Auth — set `SRE_AGENT_WEBAPI_AUTH_MODE=bearer`. RBAC
(`SRE.Viewer` / `SRE.Approver`) is unchanged.

Because the API **trusts** that forwarded token (it does not re-verify the
signature by default), two controls keep that trust boundary sound and you
should keep BOTH:

- `networkpolicy.yaml` restricts ingress to the API pods to **oauth2-proxy
  only**, so nothing in the cluster can reach the API directly and present a
  self-minted token. This needs a NetworkPolicy-capable CNI (Azure CNI +
  Calico/Cilium).
- Optionally also enable in-app JWT signature verification
  (`SRE_AGENT_WEBAPI_JWT_VERIFY=true` + the JWKS / issuer / audience settings)
  so the API independently validates the token even if it is reached directly.

## Prerequisites

- An AKS cluster with the OIDC issuer and **Workload Identity** enabled
  (`az aks update -g $RG -n $AKS --enable-oidc-issuer --enable-workload-identity`).
- **KEDA** (`az aks update -g $RG -n $AKS --enable-keda`).
- The **Key Vault Secrets Provider** addon
  (`az aks enable-addons -g $RG -n $AKS --addons azure-keyvault-secrets-provider`).
- An ingress controller (`az aks approuting enable`, or install ingress-nginx)
  and, for TLS, cert-manager or a managed certificate.
- The shared infra from the main guide: **Postgres**, the **Service Bus**
  topic + subscription, **Azure OpenAI**, **App Insights**, and a **Key Vault**
  holding the secrets listed below.

## 1. Build and push the image

One image runs the worker, the API, and the maintenance job (entrypoint
differs per workload).

```bash
ACR=<registry>.azurecr.io
az acr login -n <registry>
docker build -t $ACR/sre-agent:1.0.0 .        # repo root (has the Dockerfile)
docker push $ACR/sre-agent:1.0.0
```

## 2. Put the secrets in Key Vault

```bash
KV=<keyvault-name>
az keyvault secret set --vault-name $KV -n sre-database-url                 --value "<postgres-conn-string>"
az keyvault secret set --vault-name $KV -n sre-servicebus-connection-string --value "<servicebus-conn-string>"
az keyvault secret set --vault-name $KV -n azure-openai-api-key             --value "<aoai-key>"
az keyvault secret set --vault-name $KV -n appinsights-connection-string    --value "<appinsights-conn-string>"
az keyvault secret set --vault-name $KV -n oauth2-proxy-client-id           --value "<console-app-client-id>"
az keyvault secret set --vault-name $KV -n oauth2-proxy-client-secret       --value "<console-app-client-secret>"
az keyvault secret set --vault-name $KV -n oauth2-proxy-cookie-secret       --value "$(openssl rand -base64 32)"
```

## 3. Entra app registration for the console

- Register an app for the **console**; add a Web redirect URI
  `https://<HOST>/oauth2/callback`.
- Under **App roles**, define `SRE.Viewer` and `SRE.Approver`; assign them to
  the AD groups for your on-call and senior SRE teams.
- Client id / secret go into Key Vault (step 2).

## 4. Fill in the values and apply (turnkey)

Put your identifiers in `deploy.env` and let `apply.sh` render every `<TOKEN>`
placeholder, apply the manifests in dependency order, and smoke-check the
result:

```bash
cd sre_agent/deploy/aks
cp deploy.env.example deploy.env && $EDITOR deploy.env   # ACR, tenant, host, ...

./apply.sh render      # print the rendered manifests, apply nothing
./apply.sh dry-run     # server-side --dry-run, apply nothing
./apply.sh apply       # apply, wait for rollouts, then smoke-check
```

`deploy.env` holds identifiers (not secrets — those live in Key Vault) and is
gitignored. `apply.sh apply` waits for the oauth2-proxy / API / worker
rollouts, confirms the Key Vault secret synced and KEDA is managing the worker,
and port-forwards the API to check `/healthz` + `/readyz` (which reports
`database:true` when Postgres is reachable).

> Prefer kustomize? The manifests also work with
> `kubectl apply -k sre_agent/deploy/aks` once you've substituted the tokens
> yourself (set the image in `kustomization.yaml`).

## 5. Verify

```bash
kubectl -n sre-agent get pods,scaledobject,ingress
kubectl -n sre-agent logs deploy/sre-agent-worker      # "Listening on topic ..."
kubectl -n sre-agent get secret sre-agent-secrets      # synced from Key Vault
# Browse to https://<HOST> -> Entra login -> the console. Publish a test alert
# to the topic and watch it appear live on the dashboard.
```

Turn on step-event persistence on **both** the worker and API (it's already in
`configmap.yaml`: `SRE_AGENT_PERSIST_STEP_EVENTS=true`) so the run timeline
exists for the UI.

## What each manifest is

| File | Purpose |
| --- | --- |
| `namespace.yaml` | the `sre-agent` namespace |
| `serviceaccount.yaml` | Workload Identity SA (federated to a managed identity) |
| `configmap.yaml` | non-secret `SRE_AGENT_*` config |
| `secretproviderclass.yaml` | Key Vault CSI → synced `sre-agent-secrets` / `oauth2-proxy-secrets` |
| `data-pvc.yaml` | ReadWriteMany Azure Files PVC for knowledge/memory files |
| `worker-deployment.yaml` | the listener worker |
| `worker-scaledobject.yaml` | KEDA Service Bus autoscaling (min 1) |
| `api-deployment.yaml` | the API + SPA, `/healthz` + `/readyz` probes |
| `oauth2-proxy.yaml` | Entra login, forwards the token to the API |
| `networkpolicy.yaml` | restricts API ingress to oauth2-proxy only (protects the trusted-token boundary) |
| `ingress.yaml` | TLS entrypoint → oauth2-proxy → API |
| `maintenance-cronjob.yaml` | hourly retention (`sre_agent.main maintain`) |
| `kustomization.yaml` | ties it together; sets the image |
| `apply.sh` / `deploy.env.example` | turnkey: render placeholders → apply → smoke-check |

## Notes

- **min 1 worker replica.** The listener runs the approval-timeout and
  stalled-intake sweeps inline, so at least one pod must stay up even at zero
  traffic. Scale-to-zero is possible but then those sweeps only run when a
  message arrives — the maintenance `CronJob` still covers retention.
- **Azure Files protocol.** Prefer NFS over SMB: the file stores use fcntl
  advisory locks. In production `SRE_AGENT_DATABASE_URL` is set, so the ledger,
  approvals, incident index, and step events all use Postgres and the mount
  only holds knowledge/memory files — but NFS still avoids surprises.
- **Functions is still available.** This deployment doesn't remove the
  Functions surface (`triggers/function_app.py`); it's an alternative.
