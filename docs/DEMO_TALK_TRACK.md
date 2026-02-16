# Demo Talk Track

How to present this project in a live walkthrough. Follow this script to explain the problem, show the architecture, run the demo, and highlight the value.

---

## Opening (2 minutes)

> "SOC teams are drowning in alerts. A typical Splunk deployment generates thousands of events per day, but analysts can only deeply investigate a fraction of them. The rest get auto-closed or ignored.
>
> I built a system that automates the investigation workflow. It connects to Splunk, pulls event context, enriches indicators against threat intel, searches for known attack patterns, checks its own memory of past investigations, and sends everything to an LLM for structured analysis.
>
> The result is a triage report in 15–30 seconds instead of 15–45 minutes."

---

## Architecture (3 minutes)

Show the system diagram from README.md:

```
Splunk (:8089) → MCP Connector (:3000) → SOC Agent (:8080) → LLM (Gemini)
                                              │
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                         ChromaDB         Threat Intel      Web Search
                          (RAG)         (GreyNoise, VT)    (DuckDuckGo)
```

Walk through each component:

> "Three services running locally:
>
> 1. **Splunk** is the SIEM — it stores all security events and runs detection alerts
> 2. **MCP Connector** is a Node.js bridge that handles Splunk REST API authentication and proxies requests
> 3. **SOC Agent** is the Python backend — this is where the investigation logic lives
>
> The agent also connects to three data sources:
> - **ChromaDB** for RAG memory — stores past investigations and playbooks
> - **Threat intel APIs** — GreyNoise, AbuseIPDB, VirusTotal for IOC reputation
> - **Web search** — DuckDuckGo for campaign research and CVE lookups"

---

## Pipeline Walkthrough (3 minutes)

> "When an event comes in, the agent runs a 6-step pipeline:
>
> **Step 1** — Query Splunk for context. If the event involves IP `185.220.101.45`, the agent pulls all events from that IP in the last 24 hours — auth failures, network connections, process creation.
>
> **Step 2** — Enrich IOCs. The IP gets checked against GreyNoise, AbuseIPDB, and Shodan. Domains go to URLhaus. Hashes go to VirusTotal.
>
> **Step 3** — Web search. Looks for public threat intel on the indicators — known campaigns, CVE references.
>
> **Step 3.5** — RAG retrieval. This is the memory layer. The agent searches ChromaDB for similar past investigations, analyst feedback, and response playbooks. If someone investigated this IP last week, that context surfaces here.
>
> **Step 4** — LLM analysis. All context from steps 1–3.5 is packed into a structured prompt and sent to Gemini. The model returns a classification, severity, confidence score, MITRE technique mapping, and recommended actions.
>
> **Step 5** — Validation. Key findings from the LLM are cross-checked with additional web searches.
>
> The whole thing takes 15–30 seconds."

---

## Live Demo (10 minutes)

### Demo 1: Health Check (1 min)

> "First, let me show you everything is running."

```bash
curl http://localhost:8080/api/status/full
```

> "You can see the SOC agent is running, Splunk is connected, RAG has 34 documents loaded — 20 MITRE techniques and 3 playbooks."

### Demo 2: RAG Status (1 min)

```bash
curl http://localhost:8080/api/rag/status
```

> "The vector store has 4 collections: past investigations, analyst feedback, playbooks, and MITRE knowledge. These get searched during every investigation."

### Demo 3: Malicious Event Investigation (3 min)

> "Now let me submit a real attack scenario. This is an encoded PowerShell command from a known Tor exit node."

```bash
curl -X POST http://localhost:8080/api/investigate/comprehensive \
  -H "Content-Type: application/json" \
  -d '{
    "event_data": {
      "event_type": "process_creation",
      "host": "WORKSTATION05",
      "user": "jsmith",
      "process": "powershell.exe",
      "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
      "src_ip": "185.220.101.45"
    }
  }'
```

While waiting, narrate what's happening in the terminal:

> "Step 1 — pulling Splunk context... it found 15 related events including brute force attempts from the same IP.
>
> Step 2 — enriching IOCs... GreyNoise flagged this IP as malicious.
>
> Step 3 — web search confirms this IP is associated with known attack infrastructure.
>
> Step 3.5 — RAG retrieval found similar past investigations and the PowerShell attack playbook.
>
> Step 4 — sending everything to Gemini...
>
> Result: **true positive, critical severity, 92% confidence**. MITRE techniques T1059.001 and T1105. Recommended actions: isolate host, block IP, check for lateral movement."

### Demo 4: False Positive Detection (2 min)

> "Now let me show the system handling a false positive. This is a sysadmin running a normal PowerShell command."

```bash
curl -X POST http://localhost:8080/api/investigate/comprehensive \
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
  }'
```

> "Result: **benign, low severity**. No encoding, no download, no hidden window, launched from explorer by an admin account. This is exactly what reduces alert fatigue."

### Demo 5: RAG Learning (2 min)

> "After each investigation, the report gets stored in ChromaDB automatically. Watch the count."

```bash
# Before
curl http://localhost:8080/api/rag/status  # Note investigation count

# Submit feedback
curl -X POST http://localhost:8080/api/rag/feedback \
  -H "Content-Type: application/json" \
  -d '{"investigation_id": "INV-...", "analyst_verdict": "true_positive",
       "analyst_notes": "Confirmed. Blocked at firewall.", "analyst_name": "Suraj"}'

# After
curl http://localhost:8080/api/rag/status  # Count increased
```

> "The system now has this investigation in memory. Next time a similar event comes in, the LLM will see this past verdict and the analyst's notes. The system gets better with every investigation."

### Demo 6: Natural Language Query (1 min)

```bash
curl -X POST http://localhost:8080/api/splunk-mcp/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me all failed login attempts from external IPs"}'
```

> "You can query Splunk in plain English. The system translates it to SPL and runs the search."

---

## Closing (2 minutes)

> "To summarize:
>
> - **Problem**: SOC teams can't keep up with alert volume. Manual triage takes too long.
> - **Solution**: Automated pipeline that pulls context, enriches IOCs, searches for known threats, and uses an LLM with organizational memory to produce triage reports.
> - **Key differentiator**: The RAG memory layer. The system learns from every investigation and analyst feedback. It doesn't start from scratch each time.
> - **Result**: 15–30 second triage instead of 15–45 minutes. Every alert gets investigated, not just the ones analysts have time for."

---

## Common Questions

**Q: Does this replace SOC analysts?**
> No. It produces a recommended classification. Analysts still review and make the final call. The system learns from their feedback.

**Q: What LLM does it use?**
> Gemini by default (free tier). Also supports Claude and OpenAI. Easy to switch in the config.

**Q: What about data privacy?**
> Event data is sent to the LLM API for analysis. For production, you'd use a self-hosted model or ensure your provider's data handling meets your org's requirements.

**Q: How does RAG differ from fine-tuning?**
> Fine-tuning changes the model weights — it's expensive and requires retraining. RAG injects context at query time — it's cheaper, immediate, and the knowledge base updates with every investigation.

**Q: Can this run against a production Splunk instance?**
> Yes. Just update the `.env` with the production Splunk credentials. The system only reads from Splunk — it never writes or modifies existing data.
