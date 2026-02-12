# Architecture Documentation

Technical design documentation for the AI SOC Assistant with RAG memory layer.

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              AI SOC ASSISTANT                                    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                           USER / API CLIENT                                  ││
│  │                    (curl, Postman, Python, Browser)                         ││
│  └──────────────────────────────────┬──────────────────────────────────────────┘│
│                                     │                                            │
│                                     │ HTTP :8080                                 │
│                                     ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                         SOC AGENT (Python FastAPI)                          ││
│  │                                                                              ││
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────────┐││
│  │  │   main.py      │  │comprehensive_  │  │      rag_engine.py            │││
│  │  │  (Endpoints)   │  │  analyzer.py   │  │    (ChromaDB Vector DB)       │││
│  │  └───────┬────────┘  └───────┬────────┘  └───────────────┬────────────────┘││
│  │          │                   │                           │                  ││
│  │          └───────────────────┼───────────────────────────┘                  ││
│  │                              │                                               ││
│  │  ┌───────────────────────────┼───────────────────────────────────────────┐  ││
│  │  │                           │                                            │  ││
│  │  ▼                           ▼                           ▼                ▼  ││
│  │ splunk_mcp.py        web_enrichment.py           web_search.py    llm_analyzer││
│  │ (Splunk Native)      (IOC Enrichment)            (Web Research)   (Gemini AI) ││
│  └──┬──────────────────────────┬─────────────────────────────┬────────────────┘│
│     │                          │                             │                  │
│     │ :3000                    │                             │                  │
│     ▼                          ▼                             ▼                  │
│  ┌─────────┐            ┌──────────────┐             ┌────────────────┐        │
│  │   MCP   │            │ Threat Intel │             │  Google Gemini │        │
│  │Connector│            │    APIs      │             │      API       │        │
│  └────┬────┘            │              │             └────────────────┘        │
│       │                 │ - GreyNoise  │                                        │
│       │ :8089           │ - URLhaus    │                                        │
│       ▼                 │ - VirusTotal │                                        │
│  ┌─────────┐            └──────────────┘                                        │
│  │ SPLUNK  │                                                                    │
│  │Enterprise│                                                                   │
│  └─────────┘                                                                    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Investigation Pipeline (6 Steps)

The comprehensive investigation pipeline processes security events through 6 stages:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        INVESTIGATION PIPELINE                                    │
└─────────────────────────────────────────────────────────────────────────────────┘

  INPUT                                                                    OUTPUT
    │                                                                        ▲
    │  POST /api/investigate/comprehensive                                   │
    │  {"event_data": {...}}                                                 │
    ▼                                                                        │
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│ STEP 1  │──▶│ STEP 2  │──▶│ STEP 3  │──▶│STEP 3.5 │──▶│ STEP 4  │──▶│ STEP 5  │
│ SPLUNK  │   │   IOC   │   │   WEB   │   │   RAG   │   │   LLM   │   │VALIDATE │
│ CONTEXT │   │ ENRICH  │   │ SEARCH  │   │RETRIEVE │   │ANALYSIS │   │         │
└─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘
    │              │              │              │              │           │
    ▼              ▼              ▼              ▼              ▼           ▼
 splunk_       web_           web_          rag_           llm_        web_
 mcp.py     enrichment.py   search.py    engine.py     analyzer.py  search.py
    │              │              │              │              │           │
    │              │              │              │              │           │
    ▼              ▼              ▼              ▼              ▼           ▼
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│ Query   │   │ Query   │   │ Search  │   │ Retrieve│   │ Call    │   │Validate │
│ Splunk  │   │GreyNoise│   │DuckDuck │   │ Similar │   │ Gemini  │   │Findings │
│ for     │   │ URLhaus │   │Go for   │   │ Invest- │   │ with    │   │ with    │
│ context │   │ etc.    │   │ threat  │   │ igations│   │ all     │   │ web     │
│         │   │         │   │ intel   │   │ MITRE   │   │ context │   │ search  │
│         │   │         │   │         │   │Playbooks│   │         │   │         │
└─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘
    │              │              │              │              │           │
    │              │              │              │              │           │
    ▼              ▼              ▼              ▼              ▼           ▼
 Host &         IP/Domain      Attack       Past cases,     JSON        Verified
 User           reputation     patterns,    techniques,    analysis     report
 history        scores         techniques   playbooks       JSON


                              AFTER COMPLETION
                                    │
                                    ▼
                           ┌───────────────┐
                           │  AUTO-INGEST  │
                           │  to RAG for   │
                           │  future use   │
                           └───────────────┘
```

### Pipeline Timing

| Step | Module | What It Does | Time |
|------|--------|--------------|------|
| 1. Splunk Context | `splunk_mcp.py` | Query host/user history | 2-5s |
| 2. IOC Enrichment | `web_enrichment.py` | IP/domain/hash reputation | 3-10s |
| 3. Web Search | `web_search.py` | Research attack patterns | 2-5s |
| 3.5 RAG Retrieval | `rag_engine.py` | Find similar investigations | <1s |
| 4. LLM Analysis | `llm_analyzer.py` | AI classification | 5-30s |
| 5. Validation | `web_search.py` | Verify findings | 2-5s |

**Total**: 15-60 seconds per investigation

---

## RAG Memory Architecture

### What is RAG?

**RAG (Retrieval-Augmented Generation)** enhances AI analysis by providing relevant context from a knowledge base:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           RAG ARCHITECTURE                                       │
└─────────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────────────┐
                    │        SECURITY EVENT           │
                    │  "PowerShell encoded command"   │
                    └───────────────┬─────────────────┘
                                    │
                                    │  Text → Embedding
                                    ▼
                    ┌─────────────────────────────────┐
                    │     EMBEDDING MODEL             │
                    │  (all-MiniLM-L6-v2 via ONNX)    │
                    └───────────────┬─────────────────┘
                                    │
                                    │  [0.12, -0.34, 0.78, ...]
                                    ▼
     ┌─────────────────────────────────────────────────────────────────┐
     │                      CHROMADB VECTOR DATABASE                    │
     │                                                                  │
     │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
     │  │  INVESTIGATIONS │  │    PLAYBOOKS    │  │ MITRE_KNOWLEDGE │ │
     │  │                 │  │                 │  │                 │ │
     │  │  Past reports   │  │  SOC response   │  │  20 techniques  │ │
     │  │  Auto-ingested  │  │  procedures     │  │  T1059, T1110   │ │
     │  │  after each     │  │                 │  │  T1078, etc.    │ │
     │  │  investigation  │  │  - PowerShell   │  │                 │ │
     │  │                 │  │  - Brute Force  │  │  Descriptions,  │ │
     │  │                 │  │  - Lateral Move │  │  tactics, IOCs  │ │
     │  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
     │                                                                  │
     │  ┌─────────────────┐                                            │
     │  │ANALYST_FEEDBACK │                                            │
     │  │                 │                                            │
     │  │ Human verdicts  │                                            │
     │  │ on AI decisions │                                            │
     │  └─────────────────┘                                            │
     │                                                                  │
     └──────────────────────────────┬──────────────────────────────────┘
                                    │
                                    │  Cosine Similarity Search
                                    ▼
                    ┌─────────────────────────────────┐
                    │      TOP-K SIMILAR RESULTS      │
                    │                                 │
                    │  1. Past investigation (95%)    │
                    │  2. MITRE T1059.001 (89%)       │
                    │  3. PowerShell playbook (85%)   │
                    └───────────────┬─────────────────┘
                                    │
                                    │  Injected into LLM prompt
                                    ▼
                    ┌─────────────────────────────────┐
                    │         LLM ANALYSIS            │
                    │   (Enhanced with RAG context)   │
                    └─────────────────────────────────┘
```

### RAG Collections

| Collection | Documents | Content | Update Method |
|------------|-----------|---------|---------------|
| `investigations` | Variable | Past investigation reports | Auto-ingested |
| `analyst_feedback` | Variable | Human verdicts on AI decisions | Manual via API |
| `playbooks` | 10 chunks | SOC response procedures | Seed at startup |
| `mitre_knowledge` | 20 | MITRE ATT&CK techniques | Seed at startup |

### RAG Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         RAG LIFECYCLE                                            │
└─────────────────────────────────────────────────────────────────────────────────┘

  SEED PHASE (Startup)                    RUNTIME PHASE
  ─────────────────────                   ──────────────────────────────────────

  ┌────────────────┐                      ┌────────────────┐
  │ mitre_techniques│                     │ Investigation  │
  │    .json (20)   │──┐                  │   Request      │
  └────────────────┘  │                   └───────┬────────┘
                      │                           │
  ┌────────────────┐  │  bootstrap_               │ Step 3.5: RAG Retrieve
  │ playbooks/*.md │──┼─ knowledge()              ▼
  │ (3 files)      │  │                   ┌────────────────┐
  └────────────────┘  │                   │ rag_engine.    │
                      │                   │ retrieve_      │
  ┌────────────────┐  │                   │ context()      │
  │ demo_results   │──┘                   └───────┬────────┘
  │ .json (opt)    │                              │
  └────────────────┘                              │ Returns similar:
                                                  │ - Investigations
          │                                       │ - MITRE techniques
          │                                       │ - Playbooks
          ▼                                       ▼
  ┌────────────────┐                      ┌────────────────┐
  │   ChromaDB     │◀─────────────────────│   LLM Prompt   │
  │   (rag_data/)  │                      │   (enhanced)   │
  └───────┬────────┘                      └───────┬────────┘
          │                                       │
          │                                       ▼
          │  AUTO-INGEST                  ┌────────────────┐
          │  (after investigation)        │   Analysis     │
          │                               │   Complete     │
          │◀──────────────────────────────└────────────────┘
          │
          │  store_investigation(report)
          ▼
  ┌────────────────┐
  │ Investigation  │
  │ saved for      │
  │ future RAG     │
  └────────────────┘
```

---

## Module Architecture

### SOC Agent Modules

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SOC AGENT MODULE MAP                                     │
└─────────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │    main.py      │
                              │  (FastAPI App)  │
                              │  ~1100 lines    │
                              │  50+ endpoints  │
                              └────────┬────────┘
                                       │
         ┌─────────────┬───────────────┼───────────────┬─────────────┐
         │             │               │               │             │
         ▼             ▼               ▼               ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│comprehensive│ │ rag_engine  │ │ llm_analyzer│ │ splunk_mcp  │ │ correlation │
│ _analyzer   │ │   .py       │ │    .py      │ │    .py      │ │    .py      │
│    .py      │ │             │ │             │ │             │ │             │
│             │ │ ChromaDB    │ │ Gemini/     │ │ Native MCP  │ │ Detection   │
│ 6-step      │ │ vector      │ │ Claude/     │ │ client      │ │ rules       │
│ pipeline    │ │ store       │ │ OpenAI      │ │             │ │             │
│ orchestrator│ │             │ │             │ │             │ │             │
└──────┬──────┘ └─────────────┘ └─────────────┘ └──────┬──────┘ └─────────────┘
       │                                               │
       │                                               │
       └───────────────────┬───────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
│ web_enrichment  │ │ web_search  │ │ knowledge_store │
│      .py        │ │    .py      │ │      .py        │
│                 │ │             │ │                 │
│ - VirusTotal    │ │ - DuckDuckGo│ │ - Seed MITRE    │
│ - GreyNoise     │ │ - Serper    │ │ - Load playbooks│
│ - AbuseIPDB     │ │ - Google    │ │ - Bootstrap     │
│ - URLhaus       │ │             │ │                 │
└─────────────────┘ └─────────────┘ └─────────────────┘
```

### Module Responsibilities

| Module | Lines | Purpose |
|--------|-------|---------|
| `main.py` | ~1100 | FastAPI app, all HTTP endpoints |
| `comprehensive_analyzer.py` | ~600 | Orchestrates 6-step pipeline |
| `rag_engine.py` | ~300 | ChromaDB operations, embedding, retrieval |
| `knowledge_store.py` | ~100 | Seed MITRE, playbooks at startup |
| `llm_analyzer.py` | ~380 | Gemini/Claude/OpenAI integration |
| `splunk_mcp.py` | ~450 | Splunk Native MCP client |
| `web_enrichment.py` | ~400 | IOC enrichment APIs |
| `web_search.py` | ~620 | Web search, validation |
| `correlation.py` | ~150 | Detection rules, MITRE mapping |

---

## API Architecture

### Endpoint Map

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           API ENDPOINTS                                          │
└─────────────────────────────────────────────────────────────────────────────────┘

 HEALTH & STATUS
 ───────────────
 GET  /health                         → Service health
 GET  /api/status/full                → All components status
 GET  /api/pipeline/status            → Pipeline health

 INVESTIGATION (Main Feature)
 ────────────────────────────
 POST /api/investigate/comprehensive  → Full 6-step investigation with RAG
 POST /api/analyze/enriched           → LLM + IOC enrichment (no RAG)
 POST /api/ai/analyze                 → LLM only
 POST /api/triage/quick               → Quick severity assessment

 RAG MEMORY
 ──────────
 GET  /api/rag/status                 → RAG engine status, document counts
 POST /api/rag/search                 → Semantic search across all collections
 POST /api/rag/feedback               → Submit analyst verdict
 POST /api/rag/ingest/investigation   → Manually ingest investigation
 POST /api/rag/ingest/playbook        → Add new playbook
 POST /api/rag/seed/mitre             → Re-seed MITRE techniques
 POST /api/rag/bootstrap              → Full knowledge re-seed

 SPLUNK
 ──────
 GET  /api/splunk-mcp/test            → Test Splunk connection
 POST /api/splunk-mcp/ask             → Natural language → SPL
 POST /api/splunk-mcp/search          → Execute SPL query

 IOC ENRICHMENT
 ──────────────
 POST /api/enrich/ioc                 → Enrich single IOC
 POST /api/enrich/bulk                → Enrich multiple IOCs
 POST /api/enrich/ip                  → IP-specific enrichment
 POST /api/enrich/domain              → Domain-specific enrichment
 POST /api/enrich/hash                → Hash-specific enrichment

 WEB RESEARCH
 ────────────
 POST /api/search/web                 → General web search
 GET  /api/research/mitre/{id}        → Research MITRE technique
 GET  /api/research/cve/{id}          → Research CVE

 CORRELATION
 ───────────
 GET  /api/rules                      → List detection rules
 POST /api/correlate                  → Run correlation on events
 POST /api/mock/generate              → Generate mock alerts
```

---

## Data Models

### Investigation Report Structure

```json
{
  "status": "success",
  "investigation_id": "INV-20260212100000",
  "investigation_time_seconds": 45.2,

  "data_sources": {
    "splunk_context": {
      "host_events": 15,
      "user_events": 8,
      "ip_events": 20
    },
    "ioc_enrichment": {
      "enriched_count": 3,
      "malicious_count": 1
    },
    "web_research": {
      "sources_found": 10
    },
    "rag_context": {
      "investigations": 2,
      "mitre_techniques": 3,
      "playbooks": 1
    }
  },

  "analysis": {
    "classification": "true_positive",
    "confidence": 95,
    "severity": "critical",
    "severity_justification": "...",

    "mitre_attack": {
      "techniques": [
        {"id": "T1059.001", "name": "PowerShell", "confidence": 95}
      ],
      "tactics": ["Execution", "Defense Evasion"],
      "kill_chain_phase": "Execution"
    },

    "recommended_actions": {
      "immediate": ["Isolate host", "Block IP"],
      "short_term": ["Memory forensics", "Log review"],
      "long_term": ["EDR deployment", "Training"]
    }
  },

  "rag_ingested": true,
  "rag_doc_ids": ["inv_abc123"]
}
```

### RAG Document Structure

```json
{
  "id": "inv_20260212100000",
  "content": "Investigation of PowerShell encoded command on WORKSTATION05...",
  "metadata": {
    "type": "investigation",
    "classification": "true_positive",
    "severity": "critical",
    "techniques": ["T1059.001"],
    "timestamp": "2026-02-12T10:00:00"
  }
}
```

---

## Deployment Architecture

### Local Development

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           LOCAL MACHINE                                          │
│                                                                                  │
│   TERMINAL 1                TERMINAL 2                TERMINAL 3                │
│   ──────────                ──────────                ──────────                │
│                                                                                  │
│   Splunk Enterprise         MCP Connector             SOC Agent                 │
│   (pre-installed)           cd mcp-connector          cd soc-agent              │
│                             node index.js             python main.py            │
│                                                                                  │
│   Port 8089 ←───────────── Port 3000 ←───────────── Port 8080                  │
│                                                            │                     │
│                                                            │                     │
│                                                            ▼                     │
│                                                     ┌─────────────┐             │
│                                                     │  rag_data/  │             │
│                                                     │  ChromaDB   │             │
│                                                     │  (local)    │             │
│                                                     └─────────────┘             │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Port Summary

| Service | Port | Protocol | Start Command |
|---------|------|----------|---------------|
| Splunk Enterprise | 8089 | HTTPS | `splunk start` |
| Splunk Web UI | 8000 | HTTP | (auto with Splunk) |
| MCP Connector | 3000 | HTTP | `node index.js` |
| SOC Agent | 8080 | HTTP | `python main.py` |

---

## Security Considerations

### Credential Management

```
.env (NEVER COMMIT)
├── SPLUNK_USERNAME
├── SPLUNK_PASSWORD
├── GEMINI_API_KEY
├── VIRUSTOTAL_API_KEY
└── ...

.gitignore includes:
├── .env
├── .env.local
├── rag_data/      # Local ChromaDB storage
└── demo_results.json
```

### API Authentication

| Service | Auth Method |
|---------|-------------|
| Splunk | Basic Auth (user:pass) |
| Gemini | API Key in URL |
| GreyNoise | Optional API key |
| URLhaus | None (free) |
| DuckDuckGo | None (free) |

---

*Architecture documentation v2.0 - February 2026*
