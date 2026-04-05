# Azure Setup Guide for Support Agent

This guide walks through setting up all Azure components needed for real-world testing.

## Prerequisites

- Azure subscription with Owner or Contributor access
- Azure CLI installed (`az --version`)
- Databricks workspace (existing or new)

## Quick Start

```bash
# Login to Azure
az login

# Set your subscription
az account set --subscription "Your-Subscription-Name"

# Create resource group
az group create --name rg-support-agent --location eastus2
```

---

## 1. Azure OpenAI Setup

### Create Azure OpenAI Resource

```bash
# Create Azure OpenAI resource
az cognitiveservices account create \
  --name openai-support-agent \
  --resource-group rg-support-agent \
  --kind OpenAI \
  --sku S0 \
  --location eastus2

# Get the endpoint
az cognitiveservices account show \
  --name openai-support-agent \
  --resource-group rg-support-agent \
  --query properties.endpoint -o tsv

# Get the API key
az cognitiveservices account keys list \
  --name openai-support-agent \
  --resource-group rg-support-agent \
  --query key1 -o tsv
```

### Deploy Models

Go to [Azure OpenAI Studio](https://oai.azure.com/) and deploy:

| Model | Deployment Name | Purpose |
|-------|-----------------|---------|
| gpt-4o | gpt-4o | Primary LLM for agents |
| text-embedding-3-large | text-embedding-3-large | Vector embeddings (3072 dims) |

**Or via CLI:**

```bash
# Deploy GPT-4o (or latest available)
az cognitiveservices account deployment create \
  --name openai-support-agent \
  --resource-group rg-support-agent \
  --deployment-name gpt-4o \
  --model-name gpt-4o \
  --model-version "2024-08-06" \
  --model-format OpenAI \
  --sku-capacity 10 \
  --sku-name Standard

# Deploy embedding model
az cognitiveservices account deployment create \
  --name openai-support-agent \
  --resource-group rg-support-agent \
  --deployment-name text-embedding-3-large \
  --model-name text-embedding-3-large \
  --model-version "1" \
  --model-format OpenAI \
  --sku-capacity 10 \
  --sku-name Standard
```

### Update .env

```bash
AZURE_OPENAI_ENDPOINT=https://openai-support-agent.openai.azure.com/
AZURE_OPENAI_API_KEY=<your-key>
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_EMBEDDING_DEPLOYMENT=text-embedding-3-large
AZURE_OPENAI_API_VERSION=2024-08-06
```

---

## 2. Azure AI Search Setup

### Create Search Service

```bash
# Create Azure AI Search (Basic tier for testing)
az search service create \
  --name search-support-agent \
  --resource-group rg-support-agent \
  --sku basic \
  --location eastus2

# Get the admin key
az search admin-key show \
  --service-name search-support-agent \
  --resource-group rg-support-agent \
  --query primaryKey -o tsv
```

### Create Search Index

The index is created automatically by the application, but you can create it manually:

```bash
# Using REST API (via curl)
SEARCH_ENDPOINT="https://search-support-agent.search.windows.net"
SEARCH_KEY="<your-admin-key>"

curl -X PUT "$SEARCH_ENDPOINT/indexes/support-agent-knowledge?api-version=2024-07-01" \
  -H "Content-Type: application/json" \
  -H "api-key: $SEARCH_KEY" \
  -d '{
    "name": "support-agent-knowledge",
    "fields": [
      {"name": "id", "type": "Edm.String", "key": true},
      {"name": "content", "type": "Edm.String", "searchable": true},
      {"name": "title", "type": "Edm.String", "searchable": true},
      {"name": "category", "type": "Edm.String", "filterable": true, "facetable": true},
      {"name": "error_pattern", "type": "Edm.String", "searchable": true},
      {"name": "resolution", "type": "Edm.String", "searchable": true},
      {"name": "embedding", "type": "Collection(Edm.Single)", "dimensions": 3072, "vectorSearchProfile": "vector-profile"}
    ],
    "vectorSearch": {
      "algorithms": [{"name": "hnsw-algo", "kind": "hnsw"}],
      "profiles": [{"name": "vector-profile", "algorithm": "hnsw-algo"}]
    }
  }'
```

### Update .env

```bash
AZURE_AI_SEARCH_ENDPOINT=https://search-support-agent.search.windows.net
AZURE_AI_SEARCH_KEY=<your-admin-key>
AZURE_AI_SEARCH_INDEX=support-agent-knowledge
```

---

## 3. Azure Database for PostgreSQL Setup

### Create PostgreSQL Flexible Server

```bash
# Create PostgreSQL Flexible Server
az postgres flexible-server create \
  --name psql-support-agent \
  --resource-group rg-support-agent \
  --location eastus2 \
  --admin-user supportadmin \
  --admin-password '<StrongPassword123!>' \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --storage-size 32 \
  --version 16

# Allow Azure services to connect
az postgres flexible-server firewall-rule create \
  --resource-group rg-support-agent \
  --name psql-support-agent \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0

# Allow your IP (for local development)
MY_IP=$(curl -s ifconfig.me)
az postgres flexible-server firewall-rule create \
  --resource-group rg-support-agent \
  --name psql-support-agent \
  --rule-name AllowMyIP \
  --start-ip-address $MY_IP \
  --end-ip-address $MY_IP

# Create database
az postgres flexible-server db create \
  --resource-group rg-support-agent \
  --server-name psql-support-agent \
  --database-name supportagent
```

### Enable pgvector Extension

```bash
# Connect to PostgreSQL and enable pgvector
# Replace <your-database-password> with your actual password before running
export PGPASSWORD='<your-database-password>'
psql \
  -h psql-support-agent.postgres.database.azure.com \
  -U supportadmin \
  -d supportagent \
  -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

Or via Azure Portal:
1. Go to your PostgreSQL server
2. Settings → Server parameters
3. Search for `azure.extensions`
4. Add `VECTOR` to the list
5. Save and restart

### Run Database Migrations

```bash
# From project root
# Replace <your-database-password> with your actual password before running
export PGPASSWORD='<your-database-password>'
psql \
  -h psql-support-agent.postgres.database.azure.com \
  -U supportadmin \
  -d supportagent \
  -f scripts/init-db.sql
```

### Update .env

```bash
DATABASE_URL=postgresql://supportadmin:<password>@psql-support-agent.postgres.database.azure.com:5432/supportagent?sslmode=require
```

---

## 4. Azure Databricks Setup

### Option A: Use Existing Workspace

If you have an existing Databricks workspace:

```bash
# Get workspace URL
az databricks workspace show \
  --name your-databricks-workspace \
  --resource-group your-rg \
  --query workspaceUrl -o tsv
```

### Option B: Create New Workspace

```bash
# Create Databricks workspace
az databricks workspace create \
  --name dbx-support-agent \
  --resource-group rg-support-agent \
  --location eastus2 \
  --sku premium
```

### Generate Personal Access Token

1. Go to your Databricks workspace
2. Click your username → User Settings
3. Access tokens → Generate new token
4. Name: `support-agent`
5. Lifetime: 90 days (or as needed)
6. Copy the token

### Create Test Job (for testing)

In Databricks workspace:

```python
# Create a simple test notebook: /Shared/test-job
# Cell 1:
print("Test job started")
import time
time.sleep(10)
print("Test job completed")
```

Create a job from this notebook for testing restarts.

### Update .env

```bash
DATABRICKS_HOST=https://adb-xxxxxxxxxxxx.azuredatabricks.net
DATABRICKS_TOKEN=dapi_xxxxxxxxxxxxxxxxxxxx
```

---

## 5. Azure Service Bus Setup (Optional - for Event-Driven)

### Create Service Bus Namespace

```bash
# Create Service Bus namespace
az servicebus namespace create \
  --name sb-support-agent \
  --resource-group rg-support-agent \
  --location eastus2 \
  --sku Standard

# Create queue for incidents
az servicebus queue create \
  --name incident-queue \
  --namespace-name sb-support-agent \
  --resource-group rg-support-agent \
  --max-size 1024

# Get connection string
az servicebus namespace authorization-rule keys list \
  --resource-group rg-support-agent \
  --namespace-name sb-support-agent \
  --name RootManageSharedAccessKey \
  --query primaryConnectionString -o tsv
```

### Update .env

```bash
AZURE_SERVICEBUS_CONNECTION_STRING=Endpoint=sb://sb-support-agent.servicebus.windows.net/;SharedAccessKeyName=...
AZURE_SERVICEBUS_QUEUE_NAME=incident-queue
```

---

## 6. LangSmith Setup (Recommended for Observability)

1. Go to [smith.langchain.com](https://smith.langchain.com)
2. Create an account/organization
3. Generate API key

### Update .env

```bash
LANGCHAIN_API_KEY=lsv2_pt_xxxxxxxxxxxxxxxxxxxx
LANGCHAIN_PROJECT=support-agent
LANGCHAIN_TRACING_V2=true
```

---

## Complete .env File

Create `.env` from template:

```bash
cp .env.example .env
```

Fill in all values:

```bash
# Environment
ENVIRONMENT=development
LOG_LEVEL=INFO

# Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://openai-support-agent.openai.azure.com/
AZURE_OPENAI_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_EMBEDDING_DEPLOYMENT=text-embedding-3-large
AZURE_OPENAI_API_VERSION=2024-08-06

# Azure AI Search
AZURE_AI_SEARCH_ENDPOINT=https://search-support-agent.search.windows.net
AZURE_AI_SEARCH_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AZURE_AI_SEARCH_INDEX=support-agent-knowledge

# Database
DATABASE_URL=postgresql://supportadmin:password@psql-support-agent.postgres.database.azure.com:5432/supportagent?sslmode=require

# Databricks
DATABRICKS_HOST=https://adb-xxxxxxxxxxxx.azuredatabricks.net
DATABRICKS_TOKEN=dapi_xxxxxxxxxxxxxxxxxxxx

# LangSmith (optional but recommended)
LANGCHAIN_API_KEY=lsv2_pt_xxxxxxxxxxxxxxxxxxxx
LANGCHAIN_PROJECT=support-agent
LANGCHAIN_TRACING_V2=true

# API Security
API_KEYS=your-secure-api-key-here
```

---

## 7. Verify Setup

### Test Connections

```bash
# Install dependencies
pip install -r requirements.txt

# Run connection tests
python -c "
import asyncio
from src.integrations.config import get_settings
from src.integrations.llm_client import get_llm_client
from src.integrations.databricks_client import get_databricks_client

async def test():
    settings = get_settings()
    print(f'Environment: {settings.environment}')

    # Test LLM
    llm = get_llm_client()
    response = await llm.chat_completion([{'role': 'user', 'content': 'Say hello'}])
    print(f'LLM Response: {response[:50]}...')

    # Test Databricks
    dbx = get_databricks_client()
    clusters = await dbx.list_clusters()
    print(f'Databricks clusters: {len(clusters)}')

    print('All connections successful!')

asyncio.run(test())
"
```

### Start the API

```bash
# Run the API locally
uvicorn src.api.main:app --reload --port 8000

# Test health endpoint
curl http://localhost:8000/health/live
```

### Send a Test Incident

```bash
curl -X POST http://localhost:8000/api/v1/incidents \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secure-api-key-here" \
  -d '{
    "job_name": "test-etl-job",
    "job_type": "databricks",
    "source_system": "Azure-EastUS",
    "environment": "dev",
    "error_message": "OutOfMemoryError: Java heap space",
    "priority_hint": "P3"
  }'
```

---

## Cost Estimates (Monthly)

| Service | SKU | Est. Cost |
|---------|-----|-----------|
| Azure OpenAI | Pay-as-you-go | $50-200 (depends on usage) |
| Azure AI Search | Basic | ~$75 |
| PostgreSQL Flexible | B1ms | ~$15 |
| Databricks | Existing/Jobs | Variable |
| Service Bus | Standard | ~$10 |

**Total for testing**: ~$150-300/month

---

## Cleanup

To delete all resources when done:

```bash
az group delete --name rg-support-agent --yes --no-wait
```

---

## Next Steps

1. Seed the knowledge base with known errors
2. Create test Databricks jobs for remediation testing
3. Set up monitoring dashboards in Azure
4. Configure alerts for failed incidents
