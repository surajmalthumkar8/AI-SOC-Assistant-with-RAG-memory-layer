# Alerts and Investigation Concepts

How alerts work in Splunk, how this project uses them, and how the investigation pipeline processes each one.

---

## What Is an Alert?

An alert is a saved search in Splunk that runs on a schedule. When the search returns results, Splunk fires the alert. That's it — no magic.

**Example from this project:**

```
SOC_Brute_Force_Attack
Search: index=security_events event_type=authentication action=failure
        | stats count by src_ip, dest_ip, user
        | where count >= 5
Schedule: Every 5 minutes
Lookback: Last 15 minutes
Severity: High
```

This alert runs every 5 minutes. It looks at the last 15 minutes of authentication events. If any source IP has 5+ failed logins, it fires.

---

## Where Alerts Live in Splunk

Alerts are stored as **saved searches** under:

```
Settings → Searches, Reports, and Alerts
```

Or via REST API:
```
GET /servicesNS/nobody/search/saved/searches
```

In this project, `splunk_data_loader.py` and `create_alerts.py` create 24 alerts programmatically via the Splunk REST API. They cover 9 attack scenarios:

| Alert Prefix | Scenario | Example Rule |
|-------------|----------|--------------|
| `SOC_Brute_Force_*` | Credential attacks | 5+ failed logins from same IP |
| `SOC_Encoded_PowerShell` | Malware execution | PowerShell with `-enc` or `-nop` flags |
| `SOC_Lateral_Movement` | Internal spreading | WMI/PSExec/WinRM between hosts |
| `SOC_Shadow_Copy_Deletion` | Ransomware prep | `vssadmin delete shadows` |
| `SOC_LSASS_Access` | Credential dumping | Process accessing lsass.exe |
| `SOC_DNS_Tunneling` | Data exfiltration | High-volume TXT queries to single domain |
| `SOC_Kerberoasting` | Ticket abuse | Multiple TGS requests with RC4 encryption |

---

## Detection Rules vs. Alerts

**Detection rule** = the SPL search logic that defines what to look for.

**Alert** = a detection rule + a schedule + an action. The rule runs automatically, and when it matches, something happens (log it, send email, trigger webhook, etc.).

In this project, the detection rules live inside the alert definitions in `splunk_data_loader.py`. Example:

```python
# This is the detection rule (SPL):
"search": 'index=security_events event_type=process_creation
           (process=*mimikatz* OR process=*procdump*
            OR command_line=*sekurlsa* OR command_line=*lsass.dmp*)'

# This makes it an alert:
"cron_schedule": "*/5 * * * *"   # Run every 5 min
"alert.severity": "5"            # Critical
"alert.track": "1"               # Track triggered instances
```

---

## True Positive vs. False Positive

| Term | Meaning | Example |
|------|---------|---------|
| **True Positive (TP)** | Alert fired, and it's a real threat | Encoded PowerShell downloading a payload from a known C2 IP |
| **False Positive (FP)** | Alert fired, but it's benign | Admin running `Get-Service` in PowerShell triggers the encoded command rule |
| **True Negative** | No alert, no threat | Normal web browsing |
| **False Negative** | No alert, but there IS a threat | Attacker evaded detection |

The biggest SOC problem is **false positives**. If 80% of your alerts are FPs, analysts stop paying attention. This project helps by:

1. **Enriching context before classification** — checking IPs against threat intel, looking at Splunk history
2. **RAG memory** — if an analyst marked a similar event as FP before, the system surfaces that
3. **LLM reasoning** — the model weighs all evidence, not just pattern matching

### How this project handles it

In Demo 7 (`DEMO_RUNBOOK.md`), we submit a benign admin PowerShell command:

```json
{
  "command_line": "powershell.exe Get-Service | Where-Object {$_.Status -eq Running}",
  "user": "sysadmin",
  "parent_process": "explorer.exe"
}
```

The pipeline sees:
- Normal parent process (explorer.exe → powershell.exe is standard)
- No encoding, no download, no hidden window
- User is `sysadmin` (legitimate admin account)
- No matching threat intel for the command

Result: `classification: benign`, `severity: low`

Compare with Demo 3 (the malicious case):
```json
{
  "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
  "user": "jsmith",
  "src_ip": "185.220.101.45"
}
```

The pipeline sees:
- `-nop -w hidden -enc` = classic evasion flags
- Base64 encoded payload
- Source IP on threat intel lists
- Non-admin user running encoded PowerShell

Result: `classification: true_positive`, `severity: critical`

---

## Severity Scoring

Splunk uses a 1–5 scale:

| Level | Label | Meaning |
|-------|-------|---------|
| 1 | Info | Informational, no action needed |
| 2 | Low | Minor concern, investigate when time allows |
| 3 | Medium | Worth looking at, may be suspicious |
| 4 | High | Likely malicious, investigate soon |
| 5 | Critical | Active threat, investigate immediately |

This project maps severity based on:
- **Event type weight**: Credential dumping > file access
- **IOC reputation**: Known malicious IP = severity bump
- **Attack chain position**: Exfiltration stage > reconnaissance
- **Confidence score**: Higher confidence = stricter severity

---

## Correlation

Correlation means connecting multiple events to see the bigger picture. A single failed login isn't interesting. Ten failed logins from the same IP in 5 minutes is a brute force attack.

### How this project does correlation

The `correlation.py` module has 3 rules:

1. **FailedLoginBurstRule**: Counts failed auth events per source IP. If count ≥ 5 in a 5-minute window, fires.
2. **PowerShellEncodedRule**: Looks for encoded/obfuscated PowerShell flags (`-enc`, `-nop`, `hidden`, `bypass`).
3. **MultipleProcessSpawnRule**: Detects rapid process creation from suspicious parent processes (cmd.exe, wscript.exe, cscript.exe).

### Attack chain correlation in sample data

Scenario 1 in the sample data shows a full APT chain:

```
08:30 — Brute force login (9 failures, 1 success)
08:35 — Encoded PowerShell execution (C2 payload download)
08:35 — Outbound connection to attacker IP
08:40 — Registry persistence (Run key)
08:45 — Reconnaissance (whoami, net group)
08:50 — Lateral movement (WMI, PSExec, WinRM)
09:00 — Data exfiltration (7z archive → curl upload)
```

The comprehensive analyzer (Step 1) queries Splunk for events from the same `src_ip`, `host`, and `user`. This means even if you submit just the PowerShell event, the pipeline pulls in the brute force, lateral movement, and exfiltration events automatically.

---

## SOC Triage Steps

Traditional triage (what an analyst does manually):

```
1. Receive alert
2. Read the event data → what happened?
3. Check the source → who/what triggered this?
4. Search for context → has this IP/user done this before?
5. Enrich IOCs → is this IP known malicious?
6. Classify → real threat or false positive?
7. Assign severity → how bad is it?
8. Recommend action → block? isolate? monitor?
9. Document → write up findings
```

This project automates steps 2–9. Step 1 (receiving the alert) can be automated via the alert monitor, or events can be submitted manually via API.

---

## MITRE ATT&CK Mapping

MITRE ATT&CK is a framework that catalogs attacker techniques. Each technique has an ID:

| ID | Name | Tactic | Example from Sample Data |
|------|------|--------|------------------------|
| T1110.001 | Brute Force: Password Guessing | Credential Access | 9 failed logins from 185.220.101.45 |
| T1059.001 | PowerShell | Execution | `powershell.exe -enc SQBFAFgA...` |
| T1105 | Ingress Tool Transfer | Command and Control | Downloading payload via WebClient |
| T1547.001 | Registry Run Keys | Persistence | Setting `HKLM\...\Run\WindowsUpdate` |
| T1021.006 | WinRM | Lateral Movement | `Invoke-Command -ComputerName DC01` |
| T1003.001 | LSASS Memory | Credential Access | `procdump.exe -ma lsass.exe` |
| T1558.003 | Kerberoasting | Credential Access | Multiple TGS requests with RC4 |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | DNS TXT query tunneling |

### How this project uses MITRE

1. **RAG seed data**: 20 technique descriptions are loaded into ChromaDB on startup from `knowledge/mitre_techniques.json`
2. **Sample data**: Every event in `security_events.json` has `_mitre_techniques` metadata
3. **Alert descriptions**: Each Splunk alert includes the relevant technique ID
4. **LLM output**: The investigation report includes mapped MITRE technique IDs

---

## What Happens Inside the Pipeline — Detailed

Here's exactly what happens when you POST to `/api/investigate/comprehensive`:

### Request
```json
POST /api/investigate/comprehensive
{
  "event_data": {
    "event_type": "process_creation",
    "host": "WORKSTATION05",
    "user": "jsmith",
    "process": "powershell.exe",
    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
    "src_ip": "185.220.101.45"
  }
}
```

### Step 1 — Splunk Context (`splunk_mcp.py`)

Module: `comprehensive_analyzer._get_splunk_context()`

Runs 4 SPL queries against Splunk:
```
1. index=security_events src_ip="185.220.101.45" | head 20
2. index=security_events host="WORKSTATION05" | head 20
3. index=security_events user="jsmith" event_type=authentication | head 10
4. Asks natural language: "Show events related to 185.220.101.45"
```

Returns: related events, auth history, network connections.

### Step 2 — IOC Enrichment (`web_enrichment.py`)

Module: `comprehensive_analyzer._enrich_iocs()`

Extracts IOCs from the event (IPs, domains, hashes) and queries:
- GreyNoise → Is `185.220.101.45` scanning the internet?
- URLhaus → Any malware URLs associated?
- AbuseIPDB → Abuse reports for this IP?

Returns: reputation scores, abuse reports, known associations.

### Step 3 — Web Search (`web_search.py`)

Module: `comprehensive_analyzer._web_research()`

Searches for:
- `"185.220.101.45" threat intelligence`
- `PowerShell encoded command -nop -w hidden malware`
- Remediation guidance for the matched technique

Returns: articles, CVE references, remediation steps.

### Step 3.5 — RAG Retrieval (`rag_engine.py`)

Module: `comprehensive_analyzer._rag_retrieve()`

Builds a query string from the event data and searches all 4 ChromaDB collections. Returns top-K similar documents:
- Past investigations with similar encoded PowerShell
- Analyst feedback on similar events
- PowerShell attack response playbook
- T1059.001 technique description

### Step 4 — LLM Analysis (`comprehensive_analyzer.py`)

Module: `comprehensive_analyzer._llm_analyze()`

Builds a structured prompt that includes ALL context from steps 1–3.5:

```
You are a SOC analyst. Analyze this security event:
[event data]

Splunk context:
[related events from Step 1]

Threat intelligence:
[IOC enrichment from Step 2]

Web research:
[search results from Step 3]

Historical context (from org knowledge base):
[RAG results from Step 3.5]

Respond with JSON: classification, severity, confidence, techniques, actions
```

Sends to Gemini (or Claude/OpenAI based on config). Returns structured JSON.

### Step 5 — Validation (`comprehensive_analyzer.py`)

Module: `comprehensive_analyzer._validate_findings()`

Takes the LLM output and cross-checks key claims with additional web searches. If the LLM says "this IP is associated with APT28", the validator searches for confirmation.

### Output

Full report stored in RAG + returned to caller.

---

## Modules Used in Each Step

| Step | Primary Module | Supporting Module | API Called |
|------|---------------|-------------------|-----------|
| 1 | `comprehensive_analyzer.py` | `splunk_mcp.py` | Splunk REST API via MCP connector |
| 2 | `comprehensive_analyzer.py` | `web_enrichment.py` | GreyNoise, AbuseIPDB, Shodan, VT, URLhaus |
| 3 | `comprehensive_analyzer.py` | `web_search.py` | DuckDuckGo / Serper / Google CSE |
| 3.5 | `comprehensive_analyzer.py` | `rag_engine.py` | ChromaDB (local) |
| 4 | `comprehensive_analyzer.py` | — | Gemini / Claude / OpenAI API |
| 5 | `comprehensive_analyzer.py` | `web_search.py` | DuckDuckGo / Serper |
| Store | `comprehensive_analyzer.py` | `rag_engine.py` | ChromaDB (local) |
