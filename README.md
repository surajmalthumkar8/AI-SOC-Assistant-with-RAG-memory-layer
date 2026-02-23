# SOC Investigation Assistant

Automated alert triage for Splunk. Pulls events, enriches IOCs against threat intel APIs, queries a RAG memory layer for past context, runs LLM analysis, and writes structured findings back to Splunk.

```
Splunk :8089  ──▶  MCP Connector :3000  ──▶  SOC Agent :8080  ──▶  LLM
                                                   │
                                        ┌──────────┼──────────┐
                                        ▼          ▼          ▼
                                     ChromaDB   Threat     Web Search
                                      (RAG)     Intel APIs
                                        │
                                        ▼
                            Findings ──▶ Splunk (investigation:findings)
```

## Setup

```bash
cp .env.example .env   # fill in Splunk creds + LLM API key

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

| Endpoint | Method | What it does |
|----------|--------|-------------|
| `/api/investigate/comprehensive` | POST | Full 7-step investigation pipeline |
| `/api/enrich/ioc` | POST | IOC lookup (VT, AbuseIPDB, Shodan, GreyNoise, OTX) |
| `/api/enrich/event` | POST | Extract + enrich all IOCs from an event |
| `/api/rag/status` | GET | RAG collection stats |
| `/api/rag/feedback` | POST | Submit analyst verdict/override |
| `/api/splunk-mcp/ask` | POST | Natural language Splunk query |
| `/api/splunk/search` | POST | Run SPL search via agent |
| `/api/monitor/start` | POST | Start background alert monitor |
| `/health` | GET | Health check |

## Pipeline

1. Pull host/user history from Splunk
2. Enrich IOCs against 6 threat intel APIs (parallel)
3. Web search for campaigns, CVEs, remediation
4. RAG retrieval — past investigations, analyst feedback, playbooks, MITRE techniques
5. LLM analysis (Gemini / Claude / OpenAI) with all context injected
6. Write findings back to Splunk (`sourcetype=investigation:findings`)
7. Store investigation in RAG for future reference

Query findings in Splunk:
```
index=security_events sourcetype=investigation:findings classification=true_positive
```

## Sample Data

9 attack scenarios, 100+ events, 24 alerts: APT chain, phishing, insider threat, ransomware, cryptominer, credential dumping, DNS tunneling, Kerberoasting, plus benign baseline.

```bash
cd soc-agent && python splunk_data_loader.py && python create_alerts.py
```

## License

MIT
