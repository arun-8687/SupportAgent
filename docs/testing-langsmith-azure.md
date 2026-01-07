# Testing LangSmith Observability in Azure

## Prerequisites

1. **LangSmith Account** - Free tier available at https://smith.langchain.com
2. **Azure Subscription** with deployed resources
3. **Azure CLI** installed and authenticated

---

## Step 1: Get LangSmith API Key

1. Go to https://smith.langchain.com
2. Sign up or log in
3. Go to **Settings** → **API Keys**
4. Create a new API key
5. Copy the key (starts with `lsv2_...`)

---

## Step 2: Configure Azure Environment Variables

### Option A: Azure App Service / Functions

```bash
# Set LangSmith environment variables
az webapp config appsettings set \
  --name your-support-agent-app \
  --resource-group your-rg \
  --settings \
    LANGCHAIN_TRACING_V2=true \
    LANGCHAIN_API_KEY=lsv2_your_api_key_here \
    LANGCHAIN_PROJECT=support-agent-prod \
    LANGCHAIN_ENDPOINT=https://api.smith.langchain.com
```

### Option B: Azure Key Vault (Recommended for Production)

```bash
# Store API key in Key Vault
az keyvault secret set \
  --vault-name your-keyvault \
  --name langchain-api-key \
  --value "lsv2_your_api_key_here"

# Reference in App Service
az webapp config appsettings set \
  --name your-support-agent-app \
  --resource-group your-rg \
  --settings \
    LANGCHAIN_TRACING_V2=true \
    LANGCHAIN_API_KEY=@Microsoft.KeyVault(SecretUri=https://your-keyvault.vault.azure.net/secrets/langchain-api-key/) \
    LANGCHAIN_PROJECT=support-agent-prod \
    LANGCHAIN_ENDPOINT=https://api.smith.langchain.com
```

### Option C: Docker / Container Apps

Add to your `docker-compose.yml` or container environment:

```yaml
environment:
  - LANGCHAIN_TRACING_V2=true
  - LANGCHAIN_API_KEY=${LANGCHAIN_API_KEY}
  - LANGCHAIN_PROJECT=support-agent
  - LANGCHAIN_ENDPOINT=https://api.smith.langchain.com
```

---

## Step 3: Local Testing First

Before deploying to Azure, test locally:

### 3.1 Create `.env` file

```bash
# .env
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=lsv2_your_api_key_here
LANGCHAIN_PROJECT=support-agent-dev
LANGCHAIN_ENDPOINT=https://api.smith.langchain.com

# Azure OpenAI (required for LLM calls)
AZURE_OPENAI_ENDPOINT=https://your-openai.openai.azure.com/
AZURE_OPENAI_API_KEY=your_azure_openai_key
AZURE_OPENAI_DEPLOYMENT=gpt-4
```

### 3.2 Run Test Script

```python
# scripts/test_langsmith_local.py
"""
Local test for LangSmith integration.
Run with: python scripts/test_langsmith_local.py
"""
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

async def test_langsmith():
    from src.observability import get_langsmith, langsmith

    # Check if LangSmith is enabled
    ls = get_langsmith()
    print(f"LangSmith enabled: {ls.enabled}")
    print(f"Project: {os.getenv('LANGCHAIN_PROJECT')}")

    if not ls.enabled:
        print("ERROR: LangSmith not enabled. Check LANGCHAIN_API_KEY")
        return

    # Test tracing an incident
    with ls.trace_incident(
        incident_id="TEST-001",
        job_name="test-etl-job",
        job_type="databricks",
        environment="dev",
        source_system="local-test"
    ) as run:
        print(f"Created run: {run.run_id}")

        # Simulate triage stage
        with ls.trace_stage("triage", inputs={"incident_id": "TEST-001"}):
            print("  Simulating triage...")
            await asyncio.sleep(0.1)

        # Simulate diagnosis stage
        with ls.trace_stage("diagnose", inputs={"incident_id": "TEST-001"}):
            print("  Simulating diagnosis...")
            await asyncio.sleep(0.1)

        # Simulate tool call
        with ls.trace_tool("get_job_run_details", inputs={"run_id": "12345"}):
            print("  Simulating tool call...")
            await asyncio.sleep(0.05)

        # Record classification
        run.record_classification(
            category="resource",
            confidence=0.85,
            is_known_issue=False
        )
        run.record_severity("P2")

        run.add_outputs({
            "resolution_summary": "Test completed successfully",
            "incident_closed": True
        })

    print("\n✓ Test complete! Check LangSmith UI at:")
    print(f"  https://smith.langchain.com/o/default/projects/p/{os.getenv('LANGCHAIN_PROJECT')}")

if __name__ == "__main__":
    asyncio.run(test_langsmith())
```

Run it:
```bash
python scripts/test_langsmith_local.py
```

### 3.3 Verify in LangSmith UI

1. Go to https://smith.langchain.com
2. Select your project (e.g., `support-agent-dev`)
3. You should see the test run with nested traces

---

## Step 4: Azure Integration Test

### 4.1 Create Test Endpoint

Add a test endpoint to your API (`src/api/main.py`):

```python
@app.get("/api/v1/test-langsmith")
async def test_langsmith_integration():
    """Test LangSmith connectivity."""
    from src.observability import get_langsmith

    ls = get_langsmith()

    if not ls.enabled:
        return {
            "status": "disabled",
            "message": "LangSmith not configured. Check LANGCHAIN_API_KEY."
        }

    # Create a test trace
    with ls.trace_incident(
        incident_id="AZURE-TEST-001",
        job_name="azure-connectivity-test",
        job_type="test",
        environment="azure"
    ) as run:
        run.add_outputs({"test": "successful"})
        run_id = run.run_id

    return {
        "status": "enabled",
        "project": os.getenv("LANGCHAIN_PROJECT"),
        "run_id": run_id,
        "message": "Trace created successfully. Check LangSmith UI."
    }
```

### 4.2 Deploy and Test

```bash
# Deploy to Azure (adjust for your deployment method)
az webapp deploy --name your-app --src-path .

# Test the endpoint
curl https://your-app.azurewebsites.net/api/v1/test-langsmith

# Expected response:
# {
#   "status": "enabled",
#   "project": "support-agent-prod",
#   "run_id": "abc123...",
#   "message": "Trace created successfully. Check LangSmith UI."
# }
```

---

## Step 5: End-to-End Test with Real Incident

### 5.1 Send Test Incident via API

```bash
curl -X POST https://your-app.azurewebsites.net/api/v1/incidents \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "job_name": "azure-test-etl-job",
    "job_type": "databricks",
    "source_system": "azure-test",
    "environment": "dev",
    "error_message": "java.lang.OutOfMemoryError: Java heap space",
    "error_code": "OOM_ERROR"
  }'
```

### 5.2 View Full Trace in LangSmith

1. Go to https://smith.langchain.com
2. Select project: `support-agent-prod`
3. Find the incident run: `incident:INC-xxx`
4. Expand to see:
   - `agent:triage` with classification details
   - `agent:diagnose` with hypothesis testing
   - Tool calls with inputs/outputs
   - Latency breakdown per stage

---

## Step 6: Monitor in Production

### LangSmith Dashboard Features

1. **Traces View**
   - See all incident processing runs
   - Filter by tags: `category:resource`, `severity:P1`, `auto-remediated`
   - Search by incident ID

2. **Metrics**
   - Average latency per agent/tool
   - Success/failure rates
   - Token usage and costs

3. **Debugging**
   - Click any run to see full context
   - View LLM prompts and responses
   - Replay failed runs

4. **Feedback**
   - Resolution success rates
   - Human override frequency
   - Use for evaluation/fine-tuning

### Set Up Alerts (Optional)

In LangSmith, you can set up alerts for:
- High latency runs
- Failed runs
- Unusual patterns

---

## Troubleshooting

### Issue: "LangSmith not configured"

```bash
# Verify environment variables are set
az webapp config appsettings list --name your-app --resource-group your-rg | grep LANG
```

### Issue: Traces not appearing

1. Check API key is valid (test at https://smith.langchain.com)
2. Verify network connectivity to `api.smith.langchain.com`
3. Check logs for errors:
   ```bash
   az webapp log tail --name your-app --resource-group your-rg
   ```

### Issue: Missing nested traces

Ensure you're using context managers properly:
```python
# CORRECT - nested traces
with langsmith.trace_incident(...) as run:
    with langsmith.trace_stage("triage"):
        # triage code here
        pass

# INCORRECT - traces not nested
with langsmith.trace_incident(...):
    pass
with langsmith.trace_stage("triage"):  # This won't be nested!
    pass
```

---

## Cost Considerations

LangSmith pricing (as of 2024):
- **Free tier**: 3,000 traces/month
- **Plus**: $39/month for 10,000 traces
- **Enterprise**: Custom pricing

For production, consider:
- Sampling traces (e.g., 10% of incidents)
- Only tracing errors/escalations
- Setting retention policies

### Sampling Example

```python
import random

class SampledLangSmith:
    def __init__(self, sample_rate=0.1):
        self.sample_rate = sample_rate
        self._langsmith = get_langsmith()

    def trace_incident(self, **kwargs):
        if random.random() < self.sample_rate:
            return self._langsmith.trace_incident(**kwargs)
        return DummyContextManager()
```

---

## Next Steps

1. ✅ Test locally with `.env`
2. ✅ Deploy to Azure with environment variables
3. ✅ Verify traces appear in LangSmith UI
4. ✅ Run end-to-end test with real incident
5. ⬜ Set up LangSmith alerts for production monitoring
6. ⬜ Configure sampling for high-volume production
