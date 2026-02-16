# Project Explanation — For Management

Technical summary of the AI SOC Assistant project: what problem it solves, how it works, and why it matters.

---

## The Problem

SOC teams drown in alerts. A mid-size org running Splunk might generate **5,000–10,000 alerts per day**. Each alert needs a human analyst to:

1. Open the alert
2. Look at the raw event data
3. Search Splunk for related events (same IP, same user, same host)
4. Look up IOCs (IPs, domains, hashes) on threat intel platforms
5. Check if this matches a known attack pattern
6. Decide: is this real or a false positive?
7. Document the finding
8. Take action (or close it)

**Average time per alert: 15–45 minutes.**

Most SOC teams can only investigate 10–20% of their alerts. The rest get auto-closed or age out. This means real threats get missed because analysts are stuck triaging false positives.

### Why Traditional SOC Workflows Are Slow

- **Manual context gathering**: Analysts copy-paste IPs into 4–5 different tools
- **No memory**: Every alert starts from zero. If the same IP was investigated yesterday, nobody remembers
- **Repetitive work**: 70–80% of alerts follow the same triage pattern
- **Alert fatigue**: Analysts start ignoring alerts after the 50th false positive

---

## What This System Does

This project automates the investigation workflow. When an alert fires in Splunk, the system:

1. **Pulls context from Splunk** — related events, auth logs, network connections for the same IP/host/user
2. **Enriches IOCs** — checks IPs against GreyNoise, AbuseIPDB, Shodan; checks domains against URLhaus; checks hashes against VirusTotal
3. **Searches the web** — looks for known campaigns, CVE details, and recommended remediation
4. **Checks its own memory (RAG)** — retrieves similar past investigations, analyst feedback, and response playbooks from a local vector database
5. **Sends everything to an LLM** — the model gets Splunk data + threat intel + web research + historical context, and produces a structured triage report
6. **Validates findings** — cross-checks the LLM output against additional sources

The output is a structured JSON report with:
- Classification (true positive / false positive / benign)
- Severity (critical / high / medium / low)
- Confidence score
- MITRE ATT&CK technique mapping
- Recommended response actions
- All evidence used in the decision

### Time per alert: ~15–30 seconds instead of 15–45 minutes.

---

## Where the Data Comes From

```
Splunk Enterprise (port 8089)
├── Security events (authentication, process creation, network, DNS)
├── Triggered alerts (saved searches that matched a condition)
└── Historical search results

Threat Intel APIs (optional, free tiers available)
├── GreyNoise — IP noise/malicious classification
├── AbuseIPDB — IP abuse reports
├── Shodan — open ports and services
├── VirusTotal — file/domain/IP reputation
├── URLhaus — known malware URLs
└── AlienVault OTX — threat indicators

Web Search (no API key needed)
├── DuckDuckGo (default, free)
├── Google Custom Search (optional)
└── Serper.dev (optional)

Local RAG Store (ChromaDB)
├── Past investigation reports
├── Analyst feedback and verdicts
├── SOC response playbooks
└── MITRE ATT&CK technique descriptions
```

---

## Why Splunk + MCP Connector?

Splunk's REST API uses XML/JSON over HTTPS with session-based auth. Rather than embedding Splunk API logic directly in the Python agent, we use a lightweight Node.js proxy (the MCP Connector) that:

- Handles Splunk authentication
- Translates between the agent's JSON requests and Splunk's REST API
- Manages SSL certificate handling
- Provides a clean HTTP interface the agent can call

This keeps the Python code focused on investigation logic, not HTTP plumbing.

---

## What RAG Adds

RAG (Retrieval-Augmented Generation) is the memory layer. Without it, every investigation starts from scratch — the LLM has no idea what happened yesterday.

With RAG:

- **Learning from past decisions**: If an analyst marked a similar event as a false positive last week, the system surfaces that context before the LLM makes its call
- **Playbook injection**: When the event matches a known pattern (e.g., brute force attack), the relevant response playbook is automatically included in the prompt
- **MITRE mapping**: Technique descriptions are pulled from the local store instead of requiring the LLM to hallucinate them
- **Analyst feedback loop**: Human verdicts are stored and influence future classifications

The RAG store starts with ~34 seed documents (20 MITRE techniques + 3 playbooks) and grows with every investigation.

---

## Investigation Lifecycle

```
Alert fires in Splunk
    │
    ▼
SOC Agent receives event data
    │
    ├── Step 1: Query Splunk for surrounding context
    ├── Step 2: Enrich IOCs against threat intel
    ├── Step 3: Web search for known campaigns
    ├── Step 3.5: RAG retrieval (past cases + playbooks)
    ├── Step 4: LLM analysis with all context
    └── Step 5: Cross-validate findings
    │
    ▼
Structured report generated
    │
    ├── Report auto-stored in RAG for future reference
    ├── Classification + severity + confidence returned
    └── Recommended actions provided
    │
    ▼
Analyst reviews and optionally submits feedback
    │
    └── Feedback stored in RAG → improves future triage
```

---

## Security Value

| Metric | Before | After |
|--------|--------|-------|
| Time per alert triage | 15–45 min | 15–30 sec |
| Alerts investigated per day | 10–20% | Potentially 100% |
| Context available per alert | Whatever analyst remembers | Full Splunk + threat intel + history |
| Knowledge retention | Lost when analyst leaves | Persisted in RAG store |
| False positive handling | Manual pattern recognition | Learns from past verdicts |

### What This Doesn't Replace

This is a triage assistant, not a replacement for human analysts. It:
- Produces a recommended classification, not a final decision
- Requires analyst review for critical findings
- Learns from human feedback — the analyst is still the authority

---

## Technical Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| SIEM | Splunk Enterprise | Industry standard, already deployed |
| API Bridge | Node.js + Express | Lightweight, handles Splunk REST API |
| Agent | Python + FastAPI | Async, fast, good for orchestration |
| LLM | Gemini (default) / Claude / OpenAI | Structured analysis from context |
| Vector Store | ChromaDB | Local, embedded, no infrastructure needed |
| Threat Intel | GreyNoise, AbuseIPDB, Shodan, VT | Free tiers available for all |
