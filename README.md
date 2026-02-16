# AI SOC Assistant

Automated alert triage and investigation pipeline for Splunk, backed by LLM analysis and a RAG memory layer.

Built for SOC teams that want faster triage, fewer false positives, and persistent investigation context.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Splunk    │────▶│     MCP     │────▶│  SOC Agent  │────▶│   LLM API   │
│   :8089     │     │   :3000     │     │   :8080     │     │  (Gemini)   │
└─────────────┘     └─────────────┘     └──────┬──────┘     └─────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
             ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
             │  ChromaDB   │           │   Threat    │           │    Web      │
             │  (RAG)      │           │    Intel    │           │   Search    │
             └─────────────┘           └─────────────┘           └─────────────┘
```

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Splunk Enterprise | 9.x+ | Running on `localhost:8089` |
| Node.js | 18+ | For MCP connector |
| Python | 3.9+ | For SOC agent |
| Gemini API Key | Free tier | [Get one here](https://aistudio.google.com) |

### 1. Configure Environment

Copy the example and fill in your values:

```bash
cp .env.example .env
```

At minimum, set:
```
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=<your_splunk_password>
LLM_PROVIDER=gemini
GEMINI_API_KEY=<your_key>
```

### 2. Install Dependencies

```bash
# MCP Connector
cd mcp-connector && npm install

# SOC Agent (use a virtual environment)
cd ../soc-agent
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start Services

Open two terminals:

**Terminal 1 — MCP Connector (port 3000):**
```bash
cd mcp-connector
node index.js
```

**Terminal 2 — SOC Agent (port 8080):**
```bash
cd soc-agent
python3 main.py
```

### 4. Load Sample Data (Optional)

```bash
cd soc-agent
python3 splunk_data_loader.py
```

This uploads 100+ security events covering 9 attack scenarios and creates 24 detection alerts in Splunk.

### 5. Verify

```bash
curl http://localhost:8080/health
curl http://localhost:8080/api/status/full
curl http://localhost:8080/api/rag/status
```

---

## How It Works

### Investigation Pipeline

When you submit an event to `/api/investigate/comprehensive`, the agent runs a 6-step pipeline:

```
Step 1: Query Splunk for historical context around the event
Step 2: Enrich IOCs (IPs, domains, hashes) against threat intel APIs
Step 3: Web search for known campaigns, CVEs, and remediation
Step 3.5: RAG retrieval — pull similar past investigations and playbooks
Step 4: LLM analysis — structured prompt with all context injected
Step 5: Cross-validate findings with additional lookups
Step 6: Return structured report with classification, severity, and actions
```

### RAG Memory

The system stores every investigation in ChromaDB. On the next triage, it retrieves similar past cases and injects that context into the LLM prompt. This means:

- If an analyst previously marked something as a false positive, the system remembers
- Playbooks for common attack patterns are pulled automatically
- MITRE technique descriptions are available without external lookups

**Seeded with**: 20 MITRE techniques + 3 SOC playbooks on first boot.

---

## Project Structure

```
├── .env.example                   # Configuration template
├── mcp-connector/                 # Node.js Splunk bridge
│   ├── index.js                   # Express server — proxies Splunk REST API
│   └── package.json
├── soc-agent/                     # Python investigation engine
│   ├── main.py                    # FastAPI app — all endpoints
│   ├── comprehensive_analyzer.py  # 6-step pipeline orchestrator
│   ├── rag_engine.py              # ChromaDB vector store
│   ├── knowledge_store.py         # Seeds MITRE + playbooks into RAG
│   ├── llm_analyzer.py            # Gemini / Claude / OpenAI integration
│   ├── enriched_analyzer.py       # IOC enrichment + LLM combo
│   ├── web_enrichment.py          # VirusTotal, AbuseIPDB, Shodan, etc.
│   ├── web_search.py              # DuckDuckGo / Serper / Google CSE
│   ├── splunk_mcp.py              # Direct Splunk REST client
│   ├── mcp_client.py              # MCP connector client
│   ├── correlation.py             # Rule-based event correlation
│   ├── alert_monitor.py           # Continuous alert polling
│   ├── prompts.py                 # LLM prompt templates
│   ├── config.py                  # Environment config loader
│   ├── knowledge/                 # Seed data
│   │   ├── mitre_techniques.json
│   │   └── playbooks/
│   └── requirements.txt
├── sample_data/
│   └── security_events.json       # 100+ events, 9 attack scenarios
└── test_rag.py                    # RAG validation suite
```

---

## API Reference

### Core

| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/health` | GET | Health check |
| `/api/status/full` | GET | All component status |
| `/api/investigate/comprehensive` | POST | Full 6-step investigation |
| `/api/analyze` | POST | LLM-only analysis |
| `/api/enrich/ioc` | POST | Single IOC enrichment |
| `/api/enrich/event` | POST | Full event IOC enrichment |

### RAG

| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/api/rag/status` | GET | Collection stats |
| `/api/rag/search` | POST | Semantic search across all knowledge |
| `/api/rag/feedback` | POST | Submit analyst verdict for learning |
| `/api/rag/bootstrap` | POST | Re-seed knowledge base |

### Splunk

| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/api/splunk-mcp/ask` | POST | Natural language → SPL query |
| `/api/splunk-mcp/search` | POST | Execute raw SPL |
| `/api/events` | GET | Fetch recent security events |

---

## Sample Data Scenarios

The sample data in `sample_data/security_events.json` covers:

| # | Scenario | MITRE Techniques |
|---|----------|-----------------|
| 1 | APT intrusion chain | T1110, T1059, T1105, T1547, T1021, T1048 |
| 2 | Phishing with macro payload | T1566, T1204, T1059, T1055 |
| 3 | Insider threat — USB exfil | T1078, T1530, T1052 |
| 4 | Ransomware deployment | T1110, T1021, T1490, T1486, T1489 |
| 5 | Cryptominer via web shell | T1190, T1059, T1496, T1053 |
| 6 | Normal admin activity | (baseline / false positive testing) |
| 7 | Credential dumping (LSASS) | T1003.001, T1003.002 |
| 8 | DNS tunneling | T1071.004, T1048.003 |
| 9 | Kerberoasting | T1558.003 |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Connection refused :3000` | Start MCP connector: `cd mcp-connector && node index.js` |
| `Connection refused :8080` | Start SOC agent: `cd soc-agent && python3 main.py` |
| `401 Unauthorized` | Check `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` in `.env` |
| `RAG disabled` | Set `RAG_ENABLED=true` in `.env`, install `chromadb` |
| `Gemini 429 rate limit` | Wait 60 seconds, free tier has per-minute limits |
| `chromadb install fails (M-series Mac)` | Try `pip install --no-binary :all: chroma-hnswlib` first |

---

## License

MIT
