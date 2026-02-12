# AI SOC Assistant

Local AI-powered Security Operations Center that connects **Splunk Enterprise** to an intelligent investigation pipeline with **RAG memory**.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Splunk    │────▶│     MCP     │────▶│  SOC Agent  │────▶│   Gemini    │
│   :8089     │     │   :3000     │     │   :8080     │     │     AI      │
└─────────────┘     └─────────────┘     └──────┬──────┘     └─────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
             ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
             │  ChromaDB   │           │   Threat    │           │    Web      │
             │    RAG      │           │    Intel    │           │   Search    │
             └─────────────┘           └─────────────┘           └─────────────┘
```

---

## Quick Start (5 Minutes)

### Prerequisites

| Requirement | Version | Download |
|-------------|---------|----------|
| Splunk Enterprise | 9.x / 10.x | https://splunk.com/download |
| Node.js | 18+ | https://nodejs.org |
| Python | 3.10+ | https://python.org |
| Gemini API Key | Free | https://aistudio.google.com |

### Step 1: Configure Environment

Create `.env` file in project root:

```bash
# Required - Splunk Connection
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your_password
SPLUNK_VERIFY_SSL=false

# Required - AI Provider (Gemini is free)
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key

# Service Ports
AGENT_PORT=8080
NODE_PORT=3000

# RAG Memory (auto-enabled)
RAG_ENABLED=true
RAG_TOP_K=5

# Debug
DEBUG=true
```

### Step 2: Install Dependencies

```bash
# Terminal 1: Install MCP Connector
cd mcp-connector
npm install

# Terminal 2: Install SOC Agent
cd soc-agent
pip install -r requirements.txt
```

### Step 3: Start Services

**Terminal 1 - MCP Connector:**
```bash
cd mcp-connector
node index.js
```
Expected: `[+] Server running on port 3000`

**Terminal 2 - SOC Agent:**
```bash
cd soc-agent
python main.py
```
Expected: `INFO: Uvicorn running on http://0.0.0.0:8080`

### Step 4: Verify Everything Works

```bash
# Check all services
curl http://localhost:8080/api/status/full
```

Expected output:
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

## Running Demos

### Option 1: Use Demo Runner (Recommended)

```bash
# Run ALL demos
python demo_runner.py

# Run specific demo
python demo_runner.py comprehensive    # Full investigation
python demo_runner.py rag              # RAG-specific demo (add this)
```

### Option 2: Direct API Calls

**Comprehensive Investigation (Full Pipeline + RAG):**
```bash
curl -X POST http://localhost:8080/api/investigate/comprehensive \
  -H "Content-Type: application/json" \
  -d '{
    "event_data": {
      "event_type": "process_creation",
      "host": "WORKSTATION05",
      "user": "jsmith",
      "process": "powershell.exe",
      "command_line": "powershell.exe -enc SQBFAFgA...",
      "src_ip": "185.220.101.45"
    }
  }'
```

**Check RAG Status:**
```bash
curl http://localhost:8080/api/rag/status
```

**Search RAG Knowledge:**
```bash
curl -X POST http://localhost:8080/api/rag/search \
  -H "Content-Type: application/json" \
  -d '{"query": "PowerShell encoded command", "top_k": 5}'
```

---

## Project Structure

```
splunk_ai_mcp_soc/
├── .env                        # Configuration (create this)
├── README.md                   # This file - Quick start
├── ARCHITECTURE.md             # Technical design & diagrams
├── DEMO_RUNBOOK.md             # Step-by-step demo guide
│
├── mcp-connector/              # Node.js Splunk bridge
│   ├── index.js                # Express server
│   └── package.json
│
├── soc-agent/                  # Python AI agent
│   ├── main.py                 # FastAPI endpoints
│   ├── comprehensive_analyzer.py  # 6-step investigation pipeline
│   ├── rag_engine.py           # ChromaDB vector store
│   ├── knowledge_store.py      # Knowledge seeding
│   ├── llm_analyzer.py         # Gemini/Claude/OpenAI
│   ├── web_enrichment.py       # IOC enrichment
│   ├── web_search.py           # Web research
│   ├── knowledge/              # Seed data
│   │   ├── mitre_techniques.json
│   │   └── playbooks/
│   └── requirements.txt
│
├── demo_runner.py              # Cross-platform demo script
└── test_rag.py                 # RAG test suite
```

---

## Key Features

### 1. 6-Step Investigation Pipeline

```
Event ──▶ Splunk Context ──▶ IOC Enrichment ──▶ Web Search
                                                    │
                                                    ▼
Report ◀── Validation ◀── LLM Analysis ◀── RAG Retrieval
```

### 2. RAG Memory Layer

- **Auto-learns** from past investigations
- **34 seed documents**: 20 MITRE techniques, 3 playbooks
- **Semantic search** across all knowledge

### 3. Multi-Source Intelligence

| Source | Purpose | API Key |
|--------|---------|---------|
| Splunk | Historical context | Credentials |
| GreyNoise | IP reputation | Optional |
| URLhaus | Malware URLs | None |
| DuckDuckGo | Web research | None |
| ChromaDB | RAG memory | None |

---

## API Reference

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/status/full` | GET | Full system status |
| `/api/investigate/comprehensive` | POST | Full 6-step investigation |

### RAG Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/rag/status` | GET | RAG engine status |
| `/api/rag/search` | POST | Semantic search |
| `/api/rag/feedback` | POST | Submit analyst feedback |
| `/api/rag/bootstrap` | POST | Re-seed knowledge base |

### Splunk Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/splunk-mcp/ask` | POST | Natural language query |
| `/api/splunk-mcp/search` | POST | Execute SPL |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Connection refused` | Start Splunk: `splunk start` |
| `401 Unauthorized` | Check SPLUNK_USERNAME/PASSWORD in .env |
| `RAG not active` | Run: `pip install chromadb` |
| `Gemini 429` | Rate limit - wait 1 minute |
| `Port in use` | Kill process: `netstat -ano | findstr :8080` |

### Quick Health Check

```bash
curl http://localhost:3000/health   # MCP Connector
curl http://localhost:8080/health   # SOC Agent
curl http://localhost:8080/api/rag/status  # RAG Engine
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Technical design, data flow diagrams |
| [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) | Step-by-step demo with RAG examples |

---

## License

MIT
