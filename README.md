# AI SOC Assistant

Automated alert triage pipeline for Splunk. Pulls events, enriches IOCs, runs LLM analysis, and stores results in a RAG memory layer so investigations get smarter over time.

```
Splunk :8089  ──▶  MCP Connector :3000  ──▶  SOC Agent :8080  ──▶  Gemini / Claude / OpenAI
                                                   │
                                        ┌──────────┼──────────┐
                                        ▼          ▼          ▼
                                     ChromaDB   Threat     Web Search
                                      (RAG)     Intel
```

## Setup

```bash
cp .env.example .env   # fill in Splunk creds + Gemini API key

cd mcp-connector && npm install
cd ../soc-agent && pip install -r requirements.txt
```

Start both services:
```bash
# Terminal 1
cd mcp-connector && node index.js

# Terminal 2
cd soc-agent && python main.py
```

Load sample data (optional): `cd soc-agent && python splunk_data_loader.py`

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/investigate/comprehensive` | POST | Full investigation pipeline |
| `/api/enrich/ioc` | POST | IOC enrichment (VT, AbuseIPDB, Shodan, GreyNoise, OTX) |
| `/api/enrich/event` | POST | Extract and enrich all IOCs from an event |
| `/api/analyze` | POST | LLM-only analysis |
| `/api/rag/status` | GET | RAG collection stats |
| `/api/rag/feedback` | POST | Submit analyst verdict |
| `/api/splunk-mcp/ask` | POST | Natural language Splunk query |
| `/api/events` | GET | Recent security events |

## Investigation Pipeline

1. Query Splunk for host/user history
2. Enrich IOCs against threat intel APIs
3. Web search for campaigns, CVEs, remediation
4. RAG retrieval (past investigations + playbooks)
5. LLM analysis with all context injected
6. Return classification, severity, and recommended actions

## Sample Data

9 attack scenarios (100+ events, 24 alerts): APT chain, phishing, insider threat, ransomware, cryptominer, credential dumping, DNS tunneling, Kerberoasting, plus benign baseline.

## License

MIT
