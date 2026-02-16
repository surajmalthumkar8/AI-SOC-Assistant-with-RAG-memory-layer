# Architecture

Technical design of the SOC Assistant — how the components connect, how data flows through the investigation pipeline, and how the RAG memory layer works.

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                         SOC Agent (:8080)                           │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ comprehensive │  │  enriched    │  │    llm       │              │
│  │ _analyzer.py  │  │ _analyzer.py │  │ _analyzer.py │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
│         │                  │                  │                      │
│  ┌──────▼──────────────────▼──────────────────▼───────┐             │
│  │                    main.py (FastAPI)                │             │
│  └────┬──────────┬──────────┬──────────┬──────────┬───┘             │
│       │          │          │          │          │                  │
│  ┌────▼────┐ ┌───▼───┐ ┌───▼───┐ ┌───▼────┐ ┌──▼──────┐          │
│  │ rag     │ │ web   │ │ web   │ │ splunk │ │ mcp     │          │
│  │ engine  │ │ enrich│ │ search│ │ mcp    │ │ client  │          │
│  └────┬────┘ └───┬───┘ └───┬───┘ └───┬────┘ └──┬──────┘          │
└───────┼──────────┼─────────┼─────────┼──────────┼─────────────────┘
        │          │         │         │          │
        ▼          ▼         ▼         ▼          ▼
   ┌─────────┐ ┌────────┐ ┌────────┐ ┌─────────┐ ┌─────────────┐
   │ChromaDB │ │VT/IPDB │ │DDG/    │ │ Splunk  │ │MCP Connector│
   │(local)  │ │Shodan  │ │Serper  │ │ :8089   │ │   :3000     │
   └─────────┘ └────────┘ └────────┘ └─────────┘ └──────┬──────┘
                                                         │
                                                    ┌────▼────┐
                                                    │ Splunk  │
                                                    │ REST API│
                                                    └─────────┘
```

### Components

| Component | Port | Language | Role |
|-----------|------|----------|------|
| Splunk Enterprise | 8089 | — | SIEM — event storage, search, alerts |
| MCP Connector | 3000 | Node.js | HTTP bridge to Splunk REST API |
| SOC Agent | 8080 | Python | Investigation engine — orchestrates everything |
| ChromaDB | embedded | Python | Vector store for RAG memory |

---

## Investigation Pipeline

When an event hits `/api/investigate/comprehensive`, the `comprehensive_analyzer.py` module runs 6 steps:

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│ Step 1  │──▶│ Step 2  │──▶│ Step 3  │──▶│ Step 3.5│──▶│ Step 4  │──▶│ Step 5  │
│ Splunk  │   │  IOC    │   │  Web    │   │  RAG    │   │  LLM    │   │Validate │
│ Context │   │ Enrich  │   │ Search  │   │Retrieve │   │Analysis │   │Findings │
└─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘
```

### Step Details

| Step | Module | What Happens | Time |
|------|--------|-------------|------|
| 1 | `splunk_mcp.py` | Queries Splunk for related events, auth failures, network connections from same IP/host/user | 2–5s |
| 2 | `web_enrichment.py` | Looks up IPs, domains, hashes against GreyNoise, URLhaus, VirusTotal, AbuseIPDB, Shodan | 3–10s |
| 3 | `web_search.py` | Searches DuckDuckGo/Serper for known campaigns, CVE details, remediation guidance | 2–5s |
| 3.5 | `rag_engine.py` | Retrieves similar past investigations, analyst feedback, playbooks, MITRE techniques from ChromaDB | <1s |
| 4 | `comprehensive_analyzer.py` | Builds structured prompt with all context, sends to Gemini/Claude/OpenAI | 5–30s |
| 5 | `comprehensive_analyzer.py` | Cross-validates key findings with additional web searches | 2–5s |

### Output

The pipeline returns a structured JSON report:

```json
{
  "investigation_id": "INV-20260211083000",
  "classification": "true_positive",
  "severity": "critical",
  "confidence": 92,
  "mitre_techniques": ["T1059.001", "T1105"],
  "ioc_findings": { ... },
  "recommended_actions": [ ... ],
  "rag_context_used": true,
  "pipeline_steps": { ... }
}
```

After the report is generated, it's automatically stored in the RAG vector store for future reference.

---

## RAG Memory Architecture

ChromaDB stores 4 collections. Each document is embedded as a vector for semantic similarity search.

```
┌─────────────────────────────────────────────────────┐
│                   ChromaDB (local)                  │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐                │
│  │investigations │  │analyst       │                │
│  │              │  │_feedback     │                │
│  │ Past reports │  │ Human        │                │
│  │ + outcomes   │  │ verdicts     │                │
│  └──────────────┘  └──────────────┘                │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐                │
│  │playbooks     │  │mitre         │                │
│  │              │  │_knowledge    │                │
│  │ Response     │  │ Technique    │                │
│  │ procedures   │  │ descriptions │                │
│  └──────────────┘  └──────────────┘                │
└─────────────────────────────────────────────────────┘
```

### Collections

| Collection | Contents | Seed Count | Grows How |
|------------|----------|-----------|-----------|
| `investigations` | Full investigation reports | 0 | Auto-ingested after each investigation |
| `analyst_feedback` | Human verdicts + notes | 0 | Via `/api/rag/feedback` endpoint |
| `playbooks` | Response procedures (markdown) | ~10 | Loaded from `knowledge/playbooks/` |
| `mitre_knowledge` | ATT&CK technique descriptions | ~20 | Loaded from `knowledge/mitre_techniques.json` |

### How RAG Feeds into LLM Prompts

At Step 3.5, `rag_engine.retrieve_context()` searches all 4 collections with the event data as the query. Results are formatted and injected into the LLM prompt under a "Historical Context" section:

```
Previous similar investigations:
- INV-20260210: Similar encoded PowerShell from 185.220.x.x → classified TRUE_POSITIVE
- Analyst override: "Confirmed C2 beacon, block at firewall"

Relevant playbooks:
- PowerShell Attack Response: Isolate host, check parent process tree...

MITRE techniques:
- T1059.001: Command and Scripting Interpreter: PowerShell
```

This means the LLM doesn't start from scratch — it has org-specific context from day one.

---

## Module Map

| Module | Lines | Purpose |
|--------|-------|---------|
| `main.py` | ~1120 | FastAPI app — all endpoints, request routing |
| `comprehensive_analyzer.py` | ~616 | 6-step pipeline orchestrator |
| `rag_engine.py` | ~536 | ChromaDB vector store — store, retrieve, search |
| `knowledge_store.py` | ~166 | Seeds MITRE + playbooks into RAG on startup |
| `llm_analyzer.py` | ~379 | Single-event LLM analysis (Gemini/Claude/OpenAI) |
| `enriched_analyzer.py` | ~618 | IOC enrichment + LLM combined analysis |
| `web_enrichment.py` | ~644 | Threat intel API integrations |
| `web_search.py` | ~619 | Web search (DuckDuckGo, Serper, Google) |
| `splunk_mcp.py` | ~446 | Direct Splunk REST API client |
| `mcp_client.py` | ~285 | MCP connector HTTP client |
| `correlation.py` | ~206 | Rule-based event correlation engine |
| `alert_monitor.py` | ~380 | Continuous Splunk alert polling |
| `prompts.py` | ~90 | LLM prompt templates |
| `config.py` | ~46 | Environment variable loader |

---

## API Endpoint Map

### Investigation
- `POST /api/investigate/comprehensive` — Full 6-step pipeline
- `POST /api/analyze` — LLM-only analysis
- `POST /api/analyze/enriched` — LLM + IOC enrichment
- `POST /api/triage` — Quick classification

### Splunk
- `POST /api/splunk-mcp/ask` — Natural language → SPL
- `POST /api/splunk-mcp/search` — Execute raw SPL
- `GET /api/events` — Recent events
- `GET /api/splunk-mcp/test` — Connection test

### Threat Intel
- `POST /api/enrich/ioc` — Single indicator lookup
- `POST /api/enrich/bulk` — Bulk indicator lookup
- `POST /api/enrich/event` — Full event IOC extraction + enrichment
- `POST /api/web-search/threat` — Threat research
- `POST /api/web-search/remediation` — Remediation lookup
- `POST /api/research/comprehensive` — Multi-source research

### RAG
- `GET /api/rag/status` — Collection stats
- `POST /api/rag/search` — Semantic search
- `POST /api/rag/feedback` — Submit analyst verdict
- `POST /api/rag/bootstrap` — Re-seed knowledge base
- `POST /api/rag/ingest/playbook` — Add playbook
- `POST /api/rag/ingest/investigation` — Add investigation

### System
- `GET /health` — Health check
- `GET /api/status/full` — All component status
- `GET /api/pipeline/status` — Pipeline config
- `POST /api/monitor/start` — Start alert polling
- `POST /api/monitor/stop` — Stop alert polling

---

## Environment Configuration

All config is loaded from `.env` via `python-dotenv`. See `.env.example` for the full list.

| Variable | Default | Required | Purpose |
|----------|---------|----------|---------|
| `SPLUNK_HOST` | `localhost` | Yes | Splunk management host |
| `SPLUNK_PORT` | `8089` | Yes | Splunk management port |
| `SPLUNK_USERNAME` | `admin` | Yes | Splunk credentials |
| `SPLUNK_PASSWORD` | — | Yes | Splunk credentials |
| `LLM_PROVIDER` | `gemini` | Yes | `gemini`, `openai`, or `claude` |
| `GEMINI_API_KEY` | — | If using Gemini | Google AI Studio key |
| `RAG_ENABLED` | `true` | No | Enable/disable RAG |
| `RAG_TOP_K` | `5` | No | Results per collection |
| `AGENT_PORT` | `8080` | No | SOC Agent listen port |
| `NODE_PORT` | `3000` | No | MCP Connector listen port |

---

## Security Notes

- Splunk credentials are stored in `.env`, never committed (`.gitignore`)
- API keys for threat intel services are optional — system degrades gracefully
- CORS is set to allow all origins (`*`) for local dev — restrict in production
- All Splunk API calls use `verify=False` for self-signed certs in local environments
- ChromaDB data is stored locally in `soc-agent/rag_data/` — excluded from git
