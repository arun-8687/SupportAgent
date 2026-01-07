# Complete Azure Deployment & Testing Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AZURE INFRASTRUCTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────────┐│
│  │ Service Bus  │────▶│ Azure Func   │────▶│  App Service Environment     ││
│  │ (Incidents)  │     │ (Trigger)    │     │  (Support Agent API)         ││
│  └──────────────┘     └──────────────┘     └──────────────────────────────┘│
│                                                      │                       │
│                                                      ▼                       │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────────┐│
│  │ Azure OpenAI │◀────│ LangGraph    │────▶│  PostgreSQL + pgvector       ││
│  │ (GPT-4)      │     │ Workflow     │     │  (State, Vectors, Cache)     ││
│  └──────────────┘     └──────────────┘     └──────────────────────────────┘│
│                              │                                               │
│                              ▼                                               │
│  ┌──────────────┐     ┌──────────────┐                                      │
│  │ Databricks   │◀────│ Tools        │                                      │
│  │ (Jobs API)   │     │              │                                      │
│  └──────────────┘     └──────────────┘                                      │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         OBSERVABILITY                                 │  │
│  │  LangSmith (LLM Traces) │ App Insights (Logs) │ Prometheus (Metrics) │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Note**: This guide uses App Service Environment (ASE) for hosting and PostgreSQL for all caching/session needs (no Redis required).

---

## Phase 1: Azure Infrastructure Setup

### 1.1 Create Resource Group

```bash
# Set variables
export RESOURCE_GROUP="rg-support-agent"
export LOCATION="eastus"
export ENV="dev"  # dev, staging, prod

az group create --name $RESOURCE_GROUP --location $LOCATION
```

### 1.2 Deploy PostgreSQL with pgvector

PostgreSQL handles both data storage AND caching (replacing Redis).

```bash
# Create PostgreSQL Flexible Server
az postgres flexible-server create \
  --name "psql-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --admin-user supportadmin \
  --admin-password "$(openssl rand -base64 32)" \
  --sku-name Standard_B2s \
  --tier Burstable \
  --storage-size 32 \
  --version 16

# Enable pgvector extension
az postgres flexible-server parameter set \
  --resource-group $RESOURCE_GROUP \
  --server-name "psql-support-agent-${ENV}" \
  --name azure.extensions \
  --value vector

# Create database
az postgres flexible-server db create \
  --resource-group $RESOURCE_GROUP \
  --server-name "psql-support-agent-${ENV}" \
  --database-name supportagent

# Allow Azure services
az postgres flexible-server firewall-rule create \
  --resource-group $RESOURCE_GROUP \
  --name "psql-support-agent-${ENV}" \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

### 1.3 Deploy Azure Service Bus

```bash
# Create namespace
az servicebus namespace create \
  --name "sb-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard

# Create queue for incidents
az servicebus queue create \
  --name job-failures \
  --namespace-name "sb-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --max-size 1024 \
  --default-message-time-to-live P14D

# Create topic for updates
az servicebus topic create \
  --name incident-updates \
  --namespace-name "sb-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP
```

### 1.4 Deploy Azure OpenAI

```bash
# Create Cognitive Services account
az cognitiveservices account create \
  --name "aoai-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --kind OpenAI \
  --sku S0

# Deploy GPT-4 model
az cognitiveservices account deployment create \
  --name "aoai-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --deployment-name gpt-4 \
  --model-name gpt-4 \
  --model-version "0613" \
  --model-format OpenAI \
  --sku-capacity 10 \
  --sku-name Standard

# Deploy embedding model
az cognitiveservices account deployment create \
  --name "aoai-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --deployment-name text-embedding-ada-002 \
  --model-name text-embedding-ada-002 \
  --model-version "2" \
  --model-format OpenAI \
  --sku-capacity 10 \
  --sku-name Standard
```

### 1.5 Create Key Vault for Secrets

```bash
az keyvault create \
  --name "kv-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

# Store secrets
az keyvault secret set --vault-name "kv-support-agent-${ENV}" --name "postgres-password" --value "YOUR_PASSWORD"
az keyvault secret set --vault-name "kv-support-agent-${ENV}" --name "langchain-api-key" --value "lsv2_YOUR_KEY"
az keyvault secret set --vault-name "kv-support-agent-${ENV}" --name "databricks-token" --value "YOUR_TOKEN"
az keyvault secret set --vault-name "kv-support-agent-${ENV}" --name "api-key" --value "$(openssl rand -hex 32)"
```

### 1.6 Deploy Azure Functions (Service Bus Trigger)

```bash
# Create storage account for Functions
az storage account create \
  --name "stfuncsupportagent${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS

# Create Function App
az functionapp create \
  --name "func-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --storage-account "stfuncsupportagent${ENV}" \
  --consumption-plan-location $LOCATION \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --os-type Linux

# Enable managed identity
az functionapp identity assign \
  --name "func-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP

# Get Function App identity
FUNC_IDENTITY=$(az functionapp identity show \
  --name "func-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query principalId -o tsv)

# Grant Key Vault access
az keyvault set-policy \
  --name "kv-support-agent-${ENV}" \
  --object-id $FUNC_IDENTITY \
  --secret-permissions get list

# Get Service Bus connection string
SB_CONN=$(az servicebus namespace authorization-rule keys list \
  --resource-group $RESOURCE_GROUP \
  --namespace-name "sb-support-agent-${ENV}" \
  --name RootManageSharedAccessKey \
  --query primaryConnectionString -o tsv)

# Configure Function App settings
az functionapp config appsettings set \
  --name "func-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --settings \
    "SERVICEBUS_CONNECTION=${SB_CONN}" \
    "SUPPORT_AGENT_URL=https://app-support-agent-${ENV}.azurewebsites.net" \
    "SUPPORT_AGENT_API_KEY=@Microsoft.KeyVault(SecretUri=https://kv-support-agent-${ENV}.vault.azure.net/secrets/api-key/)" \
    "ENVIRONMENT=${ENV}"
```

#### Deploy Function Code

```bash
# From the functions directory
cd functions

# Deploy to Azure
func azure functionapp publish "func-support-agent-${ENV}"

# Or deploy via zip
zip -r function.zip . -x "*.git*" -x "*__pycache__*" -x "local.settings.json"
az functionapp deployment source config-zip \
  --name "func-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --src function.zip
```

---

## Phase 2: App Service Environment Setup

### 2.1 Create App Service Environment (ASE)

```bash
# Create ASE (this takes 1-2 hours)
az appservice ase create \
  --name "ase-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --virtual-ip-type External \
  --front-end-scale-factor 15 \
  --front-end-sku I1V2

# Wait for ASE to be ready
az appservice ase show \
  --name "ase-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query "provisioningState"
```

### 2.2 Create App Service Plan in ASE

```bash
# Create App Service Plan within ASE
az appservice plan create \
  --name "asp-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --app-service-environment "ase-support-agent-${ENV}" \
  --sku I1V2 \
  --is-linux
```

### 2.3 Create Web App

```bash
# Create web app with Python runtime
az webapp create \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --plan "asp-support-agent-${ENV}" \
  --runtime "PYTHON:3.11"

# Enable managed identity
az webapp identity assign \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP

# Get the managed identity principal ID
IDENTITY_ID=$(az webapp identity show \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query principalId -o tsv)

# Grant Key Vault access to managed identity
az keyvault set-policy \
  --name "kv-support-agent-${ENV}" \
  --object-id $IDENTITY_ID \
  --secret-permissions get list
```

### 2.4 Configure Environment Variables

```bash
# Get connection strings
POSTGRES_HOST="psql-support-agent-${ENV}.postgres.database.azure.com"

SB_CONN=$(az servicebus namespace authorization-rule keys list \
  --resource-group $RESOURCE_GROUP \
  --namespace-name "sb-support-agent-${ENV}" \
  --name RootManageSharedAccessKey \
  --query primaryConnectionString -o tsv)

AOAI_KEY=$(az cognitiveservices account keys list \
  --name "aoai-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query key1 -o tsv)

AOAI_ENDPOINT=$(az cognitiveservices account show \
  --name "aoai-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query properties.endpoint -o tsv)

# Configure app settings
az webapp config appsettings set \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --settings \
    "DATABASE_HOST=${POSTGRES_HOST}" \
    "DATABASE_NAME=supportagent" \
    "DATABASE_USER=supportadmin" \
    "DATABASE_PASSWORD=@Microsoft.KeyVault(SecretUri=https://kv-support-agent-${ENV}.vault.azure.net/secrets/postgres-password/)" \
    "DATABASE_SSLMODE=require" \
    "SERVICEBUS_CONNECTION_STRING=${SB_CONN}" \
    "AZURE_OPENAI_ENDPOINT=${AOAI_ENDPOINT}" \
    "AZURE_OPENAI_API_KEY=${AOAI_KEY}" \
    "AZURE_OPENAI_DEPLOYMENT=gpt-4" \
    "EMBEDDING_DEPLOYMENT=text-embedding-ada-002" \
    "LANGCHAIN_TRACING_V2=true" \
    "LANGCHAIN_API_KEY=@Microsoft.KeyVault(SecretUri=https://kv-support-agent-${ENV}.vault.azure.net/secrets/langchain-api-key/)" \
    "LANGCHAIN_PROJECT=support-agent-${ENV}" \
    "API_KEYS=@Microsoft.KeyVault(SecretUri=https://kv-support-agent-${ENV}.vault.azure.net/secrets/api-key/)" \
    "ENVIRONMENT=${ENV}" \
    "CACHE_BACKEND=postgresql"

# Configure startup command
az webapp config set \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --startup-file "gunicorn --bind=0.0.0.0:8000 --workers=4 --worker-class=uvicorn.workers.UvicornWorker src.api.main:app"
```

### 2.5 Deploy Application Code

```bash
# Option 1: Deploy from local zip
cd /path/to/SupportAgent
zip -r deploy.zip . -x "*.git*" -x "*__pycache__*" -x "*.env*" -x "*venv*"

az webapp deployment source config-zip \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --src deploy.zip

# Option 2: Deploy from GitHub
az webapp deployment source config \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --repo-url "https://github.com/your-org/SupportAgent" \
  --branch main \
  --manual-integration
```

### 2.6 Initialize Database Schema

```bash
# Get app URL
APP_URL=$(az webapp show \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query defaultHostName -o tsv)

# Run database migrations via psql
PGPASSWORD="YOUR_PASSWORD" psql \
  -h "psql-support-agent-${ENV}.postgres.database.azure.com" \
  -U supportadmin \
  -d supportagent \
  -f infrastructure/init.sql

# Verify by hitting health endpoint
curl "https://${APP_URL}/health/ready"
```

---

## Phase 3: Testing

### 3.1 Health Check Tests

```bash
APP_URL=$(az webapp show --name "app-support-agent-${ENV}" --resource-group $RESOURCE_GROUP --query defaultHostName -o tsv)

# Test liveness
curl "https://${APP_URL}/health/live"
# Expected: {"status": "alive"}

# Test readiness (checks DB, etc.)
curl "https://${APP_URL}/health/ready"
# Expected: {"status": "healthy", "components": {...}}

# Test metrics endpoint
curl "https://${APP_URL}/metrics" | head -20
# Expected: Prometheus metrics output
```

### 3.2 LangSmith Connectivity Test

```bash
# Test LangSmith integration
curl "https://${APP_URL}/api/v1/test-langsmith"
# Expected: {"status": "enabled", "project": "support-agent-dev", "run_id": "..."}
```

### 3.3 API Authentication Test

```bash
API_KEY="your-api-key-from-keyvault"

# Without auth (should fail)
curl -X POST "https://${APP_URL}/api/v1/incidents" \
  -H "Content-Type: application/json" \
  -d '{"job_name": "test"}'
# Expected: 401 Unauthorized

# With auth (should succeed)
curl -X POST "https://${APP_URL}/api/v1/incidents" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{
    "job_name": "test-job",
    "job_type": "databricks",
    "source_system": "azure-test",
    "environment": "dev",
    "error_message": "Test error"
  }'
# Expected: {"incident_id": "INC-...", "status": "processing"}
```

### 3.4 End-to-End Incident Test

Run the full E2E test:
```bash
export APP_URL="https://app-support-agent-dev.azurewebsites.net"
export API_KEY="your-api-key"
python scripts/test_e2e_azure.py
```

### 3.5 Azure Functions Test

```bash
# Check function health
curl "https://func-support-agent-${ENV}.azurewebsites.net/api/health"
# Expected: {"status": "healthy", ...}

# View function logs
az functionapp logs tail \
  --name "func-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP

# Check function invocations
az monitor metrics list \
  --resource "func-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --resource-type "Microsoft.Web/sites" \
  --metric "FunctionExecutionCount"
```

### 3.6 Service Bus Integration Test

```bash
python scripts/test_servicebus.py
```

### 3.7 Databricks Integration Test

```bash
export TEST_DATABRICKS_JOB_ID="12345"
python scripts/test_databricks.py
```

---

## Phase 4: Load Testing

### 4.1 Using Locust

```python
# tests/load/locustfile.py
from locust import HttpUser, task, between
import random
import uuid

class SupportAgentUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self.api_key = "your-api-key"
        self.headers = {"X-API-Key": self.api_key}

    @task(10)
    def health_check(self):
        self.client.get("/health/live")

    @task(3)
    def submit_incident(self):
        error_messages = [
            "java.lang.OutOfMemoryError: Java heap space",
            "Connection reset by peer",
            "FileNotFoundException: /data/input.parquet",
            "NullPointerException in processData",
            "TimeoutException: Query took too long"
        ]

        self.client.post(
            "/api/v1/incidents",
            headers=self.headers,
            json={
                "job_name": f"load-test-job-{random.randint(1, 100)}",
                "job_type": "databricks",
                "source_system": "load-test",
                "environment": "dev",
                "error_message": random.choice(error_messages),
                "job_run_id": str(uuid.uuid4())
            }
        )

    @task(1)
    def get_metrics(self):
        self.client.get("/metrics")
```

Run load test:
```bash
pip install locust
locust -f tests/load/locustfile.py --host https://app-support-agent-dev.azurewebsites.net
```

---

## Phase 5: Monitoring & Observability

### 5.1 View LangSmith Traces

1. Go to https://smith.langchain.com
2. Select project: `support-agent-dev`
3. View traces:
   - Filter by `incident:*` for incident processing
   - Filter by `agent:triage` for triage stage
   - Filter by `tool:*` for tool executions
4. Analyze:
   - Latency breakdown per stage
   - LLM token usage
   - Error rates

### 5.2 View Prometheus Metrics

```bash
# Key metrics to monitor
curl "https://${APP_URL}/metrics" | grep -E "^support_agent"

# Incidents
support_agent_incidents_received_total
support_agent_incidents_resolved_total
support_agent_incidents_escalated_total
support_agent_active_incidents

# Performance
support_agent_incident_duration_seconds
support_agent_workflow_stage_seconds
support_agent_llm_latency_seconds

# Errors
support_agent_guardrail_violations_total
support_agent_circuit_breaker_trips_total
```

### 5.3 Application Insights Integration

```bash
# Create Application Insights
az monitor app-insights component create \
  --app "ai-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

# Get connection string
AI_CONN=$(az monitor app-insights component show \
  --app "ai-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query connectionString -o tsv)

# Add to app settings
az webapp config appsettings set \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --settings "APPINSIGHTS_CONNECTION_STRING=${AI_CONN}"
```

### 5.4 View App Service Logs

```bash
# Enable logging
az webapp log config \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --docker-container-logging filesystem

# Stream logs
az webapp log tail \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP
```

---

## Phase 6: Production Checklist

### Security
- [ ] API keys stored in Key Vault
- [ ] Managed Identity for Azure resources
- [ ] ASE network isolation configured
- [ ] TLS/SSL enabled (automatic with ASE)
- [ ] Rate limiting configured (in-memory or PostgreSQL-based)

### Reliability
- [ ] Multiple instances configured (scale out)
- [ ] Health probes configured
- [ ] Retry policies in place
- [ ] Circuit breakers enabled
- [ ] Database connection pooling

### Observability
- [ ] LangSmith traces flowing
- [ ] Prometheus metrics exposed
- [ ] Application Insights connected
- [ ] Alerts configured for failures
- [ ] Audit logging enabled

### Performance
- [ ] Load tested at expected volume
- [ ] Database indexes created
- [ ] PostgreSQL-based caching for rate limits
- [ ] LLM response times acceptable

### Operations
- [ ] Runbook documentation complete
- [ ] On-call rotation defined
- [ ] Escalation paths documented
- [ ] Disaster recovery tested

---

## Troubleshooting

### App not starting
```bash
# Check logs
az webapp log tail --name "app-support-agent-${ENV}" --resource-group $RESOURCE_GROUP

# Check deployment status
az webapp deployment list-publishing-profiles \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP
```

### Database connection issues
```bash
# Test connectivity from Cloud Shell or local
PGPASSWORD="YOUR_PASSWORD" psql \
  -h "psql-support-agent-${ENV}.postgres.database.azure.com" \
  -U supportadmin \
  -d supportagent \
  -c "SELECT 1"

# Check firewall rules
az postgres flexible-server firewall-rule list \
  --resource-group $RESOURCE_GROUP \
  --name "psql-support-agent-${ENV}"
```

### LangSmith traces not appearing
```bash
# Check env vars
az webapp config appsettings list \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP | grep LANG

# Test endpoint
curl "https://${APP_URL}/api/v1/test-langsmith"
```

### Service Bus not receiving
```bash
# Check queue depth
az servicebus queue show \
  --name job-failures \
  --namespace-name "sb-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query "countDetails"
```

### Scaling issues
```bash
# Scale out App Service
az webapp scale \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --instance-count 3

# Check current scale
az webapp show \
  --name "app-support-agent-${ENV}" \
  --resource-group $RESOURCE_GROUP \
  --query "siteConfig.numberOfWorkers"
```

---

## Cost Optimization

### ASE Considerations
- ASE has a base cost regardless of apps running
- Consider ASEv3 for better pricing
- Use auto-scaling to minimize instances during off-hours

### PostgreSQL
- Use Burstable tier for dev/test
- Scale to General Purpose for production
- Enable connection pooling (PgBouncer)

### Azure OpenAI
- Monitor token usage via metrics
- Set up spending limits
- Consider provisioned throughput for high volume
