# Demo Runbook

Step-by-step guide for demonstrating the SOC Assistant pipeline and RAG memory.

Commands are shown for both **PowerShell** (Windows) and **Bash** (macOS/Linux).

---

## Prerequisites

| Component | Check | Version |
|-----------|-------|---------|
| Node.js | `node --version` | 18+ |
| Python | `python3 --version` | 3.9+ |
| Splunk | Running on `:8089` | 9.x+ |
| `.env` | Configured | See `.env.example` |

### Install

```bash
# MCP connector
cd mcp-connector && npm install

# SOC agent
cd soc-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

---

## Start Services

### Terminal 1 — MCP Connector
```bash
cd mcp-connector
node index.js
# Expected: [+] Server running on port 3000
```

### Terminal 2 — SOC Agent
```bash
cd soc-agent
python3 main.py
# Expected: INFO: Uvicorn running on http://0.0.0.0:8080
```

### Load Sample Data (one-time)
```bash
cd soc-agent
python3 splunk_data_loader.py
```

---

## Health Check

**Bash:**
```bash
curl -s http://localhost:3000/health
curl -s http://localhost:8080/health
curl -s http://localhost:8080/api/status/full | python3 -m json.tool
```

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/health"
Invoke-RestMethod -Uri "http://localhost:8080/health"
Invoke-RestMethod -Uri "http://localhost:8080/api/status/full" | ConvertTo-Json -Depth 5
```

Expected:
```json
{
  "soc_agent": "running",
  "components": { "mcp_connector": "running", "splunk": "connected" },
  "llm": { "enabled": true, "provider": "gemini" },
  "rag": { "status": "active", "total_documents": 34 }
}
```

---

## Demo 1: RAG Status

Shows the vector store collections and document counts.

**Bash:**
```bash
curl -s http://localhost:8080/api/rag/status | python3 -m json.tool
```

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/rag/status" | ConvertTo-Json -Depth 3
```

Output:
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

## Demo 2: RAG Semantic Search

Search the knowledge base by meaning, not keywords.

**Bash:**
```bash
curl -s -X POST http://localhost:8080/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{"query": "encoded PowerShell command execution", "top_k": 3}' \
  | python3 -m json.tool
```

**PowerShell:**
```powershell
$body = @{ query = "encoded PowerShell command execution"; top_k = 3 } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/rag/search" `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5
```

Returns matching MITRE techniques, playbooks, and past investigations ranked by relevance.

---

## Demo 3: Full Investigation (6-Step Pipeline)

This is the main demo. Submits a suspicious encoded PowerShell event and runs the complete pipeline.

**Bash:**
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
      "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
      "pid": 4532,
      "ppid": 2048,
      "src_ip": "185.220.101.45"
    }
  }' | python3 -m json.tool
```

**PowerShell:**
```powershell
$body = @{
    event_data = @{
        event_type = "process_creation"
        host = "WORKSTATION05"
        user = "jsmith"
        parent_process = "explorer.exe"
        process = "powershell.exe"
        command_line = "powershell.exe -nop -w hidden -enc SQBFAFgA..."
        pid = 4532
        ppid = 2048
        src_ip = "185.220.101.45"
    }
} | ConvertTo-Json -Depth 3
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/investigate/comprehensive" `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
```

**Watch the agent terminal for pipeline steps:**
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

## Demo 4: RAG Learning Loop

Show that investigation count increases after each run.

**Bash:**
```bash
# Before
curl -s http://localhost:8080/api/rag/status | python3 -c \
  "import sys,json; print('investigations:', json.load(sys.stdin)['collections']['investigations'])"

# Run the investigation from Demo 3...

# After
curl -s http://localhost:8080/api/rag/status | python3 -c \
  "import sys,json; print('investigations:', json.load(sys.stdin)['collections']['investigations'])"
```

The count should increase by 1 after each investigation.

---

## Demo 5: Analyst Feedback

Submit a human verdict that the system will use in future triage.

**Bash:**
```bash
curl -s -X POST http://localhost:8080/api/rag/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "INV-20260212100001",
    "analyst_verdict": "true_positive",
    "analyst_notes": "Confirmed malicious. Isolated host and blocked IP at firewall.",
    "analyst_name": "Suraj"
  }' | python3 -m json.tool
```

**PowerShell:**
```powershell
$body = @{
    investigation_id = "INV-20260212100001"
    analyst_verdict = "true_positive"
    analyst_notes = "Confirmed malicious. Isolated host and blocked IP at firewall."
    analyst_name = "Suraj"
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/rag/feedback" `
  -ContentType "application/json" -Body $body
```

---

## Demo 6: Natural Language Splunk Query

Ask a question in plain English and get SPL + results back.

**Bash:**
```bash
curl -s -X POST http://localhost:8080/api/splunk-mcp/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me all failed login attempts from external IPs"}' \
  | python3 -m json.tool
```

**PowerShell:**
```powershell
$body = @{ question = "Show me all failed login attempts from external IPs" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/splunk-mcp/ask" `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5
```

---

## Demo 7: False Positive Detection

Submit a benign admin event. The system should classify it correctly.

**Bash:**
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

Expected: `classification: benign`, `severity: low`

---

## Demo 8: IOC Enrichment

Look up a suspicious IP across multiple threat intel sources.

**Bash:**
```bash
curl -s -X POST http://localhost:8080/api/enrich/ioc \
  -H "Content-Type: application/json" \
  -d '{"indicator": "185.220.101.45"}' | python3 -m json.tool
```

**PowerShell:**
```powershell
$body = @{ indicator = "185.220.101.45" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/enrich/ioc" `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5
```

---

## Demo 9: MITRE Technique Lookup

Search RAG for MITRE technique details.

**Bash:**
```bash
curl -s -X POST http://localhost:8080/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{"query": "T1110 brute force credential access", "top_k": 3}' \
  | python3 -m json.tool
```

---

## Using demo_runner.py

Cross-platform alternative — runs demos without manual curl commands:

```bash
python3 demo_runner.py                  # Run all demos
python3 demo_runner.py comprehensive    # Full investigation only
python3 demo_runner.py nlquery          # Natural language query
python3 demo_runner.py enrich           # IOC enrichment
python3 demo_runner.py falsepositive    # False positive test
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| PowerShell `curl` returns HTML | Use `Invoke-RestMethod` instead |
| `Connection refused` | Start both services (Terminals 1 and 2) |
| `RAG status: disabled` | Set `RAG_ENABLED=true` in `.env` |
| `0 documents` in RAG | POST to `/api/rag/bootstrap` |
| `Gemini 429` | Wait 60 seconds (rate limit) |

**PowerShell tips:**
- Use `Invoke-RestMethod`, not `curl` (which is aliased to `Invoke-WebRequest`)
- Pipe output to `ConvertTo-Json -Depth 5` for readable nested JSON
- Escape `$` in strings with backtick: `` `$_.Status ``
