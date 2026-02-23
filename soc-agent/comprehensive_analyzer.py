"""
Comprehensive Security Analyzer
Runs the full 6-step investigation pipeline:
  1. Pull event context from Splunk (via MCP)
  2. Enrich IOCs against threat intel APIs
  3. Web search for validation / known campaigns
  3.5 RAG retrieval for org-specific context
  4. LLM analysis (Gemini / Claude / OpenAI)
  5. Cross-validate findings
  6. Return structured investigation report
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx

from config import config
from splunk_mcp import splunk_mcp_server, ask_splunk_natural, search_splunk_mcp
from web_search import (
    web_search, security_researcher, comprehensive_researcher,
    research_for_event_triage, validate_finding, search_remediation
)
from web_enrichment import threat_intel, enrich_event_iocs
from rag_engine import rag_engine

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [COMPREHENSIVE-ANALYZER] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:500]}")


COMPREHENSIVE_PROMPT = """You are an expert SOC (Security Operations Center) analyst conducting a comprehensive investigation.

## Security Event
```json
{event_data}
```

## Splunk Context (Historical Data from SIEM)
```json
{splunk_context}
```

## Threat Intelligence Enrichment (API Sources)
```json
{threat_intel}
```

## Web Research Findings (Internet Sources)
```json
{web_research}
```

## Organizational Context (RAG - Past Incidents, Playbooks & Analyst Feedback)
```json
{rag_context}
```
This section contains knowledge retrieved from the organization's memory:
- **Similar past investigations** - how similar events were classified before
- **Analyst feedback** - analyst overrides and notes on past AI classifications
- **Relevant playbooks** - SOC procedures for this type of event
- **MITRE ATT&CK context** - technique details from the knowledge base
Use this context to align your analysis with the organization's historical decisions and procedures.
If an analyst previously overrode an AI classification for a similar event, weight that feedback heavily.

## Your Comprehensive Analysis Tasks

Based on ALL the above data sources, provide a thorough investigation:

1. **Event Classification**: True Positive / False Positive / Benign True Positive
   - Cite specific evidence from each data source

2. **Confidence Assessment**: 0-100%
   - Explain what increases/decreases your confidence
   - Note any conflicting information between sources

3. **Severity Rating**: Critical / High / Medium / Low
   - Justify based on potential impact and evidence

4. **MITRE ATT&CK Analysis**:
   - Map to specific techniques with IDs
   - Identify the attack chain phase
   - Note any related techniques

5. **Threat Attribution**:
   - Possible threat actors (cite web research sources)
   - Malware families
   - Known campaigns

6. **IOC Analysis**:
   - Summarize findings for each IOC
   - Note reputation scores from threat intel
   - Highlight any web research confirmations

7. **Validated Findings**:
   - List findings confirmed by multiple sources
   - Note any findings that couldn't be validated
   - Highlight contradictory information

8. **Recommended Actions**:
   - Immediate (within 1 hour)
   - Short-term (within 24 hours)
   - Long-term (ongoing improvements)
   - Include specific remediation steps from web research

9. **Investigation Queries**:
   - Splunk SPL queries for further investigation
   - Questions to ask Splunk in natural language

10. **Sources & References**:
    - List all web sources that informed the analysis
    - Note reliability of each source

## Response Format
Provide your analysis in JSON:
```json
{{
    "classification": "true_positive|false_positive|benign_true_positive",
    "confidence": 0-100,
    "confidence_breakdown": {{
        "splunk_evidence": "description",
        "threat_intel_evidence": "description",
        "web_research_evidence": "description",
        "conflicting_info": []
    }},
    "severity": "critical|high|medium|low",
    "severity_justification": "...",
    "mitre_attack": {{
        "techniques": [{{"id": "T1XXX", "name": "...", "evidence": "..."}}],
        "tactics": [],
        "kill_chain_phase": "..."
    }},
    "threat_attribution": {{
        "threat_actors": [{{"name": "...", "confidence": "high|medium|low", "source": "..."}}],
        "malware_families": [],
        "campaigns": []
    }},
    "ioc_analysis": [
        {{"ioc": "...", "type": "...", "verdict": "...", "sources": []}}
    ],
    "validated_findings": {{
        "confirmed": [{{"finding": "...", "sources": []}}],
        "unconfirmed": [],
        "contradictory": []
    }},
    "recommended_actions": {{
        "immediate": [{{"action": "...", "reason": "...", "source": "..."}}],
        "short_term": [],
        "long_term": []
    }},
    "investigation_queries": {{
        "spl": [],
        "natural_language": []
    }},
    "sources_references": [
        {{"title": "...", "url": "...", "relevance": "..."}}
    ],
    "analyst_summary": "..."
}}
```
"""


class ComprehensiveAnalyzer:
    """
    Full-stack security analyzer using:
    - Splunk MCP for SIEM data
    - Threat Intel APIs for IOC enrichment
    - Web Search for research and validation
    - LLM for structured analysis
    """

    def __init__(self):
        self.provider = LLM_PROVIDER

        if self.provider == "gemini":
            self.api_key = GEMINI_API_KEY
        elif self.provider == "anthropic":
            self.api_key = ANTHROPIC_API_KEY
        else:
            self.api_key = OPENAI_API_KEY

        self.enabled = bool(self.api_key)
        log(f"Comprehensive Analyzer initialized", {
            "provider": self.provider,
            "enabled": self.enabled
        })

    async def full_investigation(self, event_data: Dict) -> Dict:
        """
        Complete investigation pipeline:
        1. Query Splunk for context
        2. Enrich IOCs from APIs
        3. Research via web search
        4. Analyze with LLM
        5. Validate and return report
        """
        log("Starting comprehensive investigation", {
            "event_type": event_data.get("event_type")
        })

        investigation_start = datetime.now()

        log("Step 1: Querying Splunk MCP for context...")
        splunk_context = await self._get_splunk_context(event_data)

        log("Step 2: Enriching IOCs...")
        threat_intel_data = await self._enrich_iocs(event_data)

        log("Step 3: Web search...")
        web_research = await self._web_research(event_data)

        log("Step 3.5: RAG retrieval...")
        rag_context = self._rag_retrieve(event_data)

        log("Step 4: LLM analysis...")
        if self.enabled:
            analysis = await self._llm_analyze(
                event_data, splunk_context, threat_intel_data, web_research, rag_context
            )
        else:
            analysis = self._rule_based_analyze(
                event_data, splunk_context, threat_intel_data, web_research
            )

        # validate key findings
        log("Step 5: Validating key findings...")
        validated_analysis = await self._validate_findings(analysis, event_data)

        # compile report
        investigation_time = (datetime.now() - investigation_start).total_seconds()

        report = {
            "status": "success",
            "investigation_id": f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "investigation_time_seconds": investigation_time,
            "event_data": event_data,
            "data_sources": {
                "splunk_mcp": splunk_context,
                "threat_intel": threat_intel_data,
                "web_research": web_research,
                "rag_context": rag_context
            },
            "analysis": validated_analysis,
            "llm_provider": self.provider if self.enabled else "rule_based"
        }

        log("Investigation complete", {
            "classification": validated_analysis.get("classification"),
            "severity": validated_analysis.get("severity"),
            "time": f"{investigation_time:.1f}s"
        })

        # store in RAG for future lookups
        try:
            rag_result = rag_engine.store_investigation(report)
            report["rag_ingested"] = True
            report["rag_doc_ids"] = rag_result.get("doc_ids", [])
            log("Investigation auto-ingested into RAG", rag_result)
        except Exception as e:
            log(f"RAG auto-ingest failed (non-fatal): {e}")
            report["rag_ingested"] = False

        # write findings back to Splunk
        try:
            if config.SPLUNK_WRITEBACK_ENABLED:
                splunk_finding = self._format_splunk_findings(report)
                await splunk_mcp_server.ingest_event(
                    index=config.SPLUNK_FINDINGS_INDEX,
                    sourcetype=config.SPLUNK_FINDINGS_SOURCETYPE,
                    event_data=splunk_finding
                )
                report["splunk_writeback"] = True
                log("Findings written to Splunk", {
                    "index": config.SPLUNK_FINDINGS_INDEX,
                    "sourcetype": config.SPLUNK_FINDINGS_SOURCETYPE,
                    "investigation_id": report.get("investigation_id")
                })
        except Exception as e:
            log(f"Splunk write-back failed (non-fatal): {e}")
            report["splunk_writeback"] = False

        return report

    def _format_splunk_findings(self, report: Dict) -> Dict:
        """Flatten investigation report into a Splunk-optimized event.
        Top-level fields are flat for fast searching, nested objects
        stay under full_analysis for spath drill-down."""
        event_data = report.get("event_data", {})
        analysis = report.get("analysis", {})
        mitre = analysis.get("mitre_attack", {})

        technique_ids, technique_names = [], []
        for t in mitre.get("techniques", []):
            if isinstance(t, dict):
                technique_ids.append(t.get("id", ""))
                technique_names.append(t.get("name", ""))
            elif isinstance(t, str):
                technique_ids.append(t)

        tactics = mitre.get("tactics", [])
        tactics_str = ",".join(str(t) for t in tactics) if isinstance(tactics, list) else str(tactics)

        attribution = analysis.get("threat_attribution", {})
        actor_names = []
        for a in attribution.get("threat_actors", []):
            if isinstance(a, dict):
                actor_names.append(a.get("name", ""))
            elif isinstance(a, str):
                actor_names.append(a)

        return {
            "investigation_id": report.get("investigation_id", ""),
            "original_event_type": event_data.get("event_type", "unknown"),
            "original_host": event_data.get("host", ""),
            "original_user": event_data.get("user", ""),
            "original_src_ip": event_data.get("src_ip", ""),
            "original_dest_ip": event_data.get("dest_ip", ""),
            "original_event_time": event_data.get("_time", ""),
            "classification": analysis.get("classification", "unknown"),
            "severity": analysis.get("severity", "unknown"),
            "confidence": analysis.get("confidence", 0),
            "severity_justification": analysis.get("severity_justification", ""),
            "mitre_technique_ids": ",".join(technique_ids),
            "mitre_technique_names": ",".join(technique_names),
            "mitre_tactics": tactics_str,
            "mitre_kill_chain_phase": mitre.get("kill_chain_phase", ""),
            "threat_actors": ",".join(actor_names),
            "malware_families": ",".join(str(m) for m in attribution.get("malware_families", [])),
            "investigated_by": "AI_SOC_Agent",
            "llm_provider": report.get("llm_provider", "unknown"),
            "investigation_time_sec": report.get("investigation_time_seconds", 0),
            "investigation_timestamp": report.get("timestamp", ""),
            "rag_context_used": report.get("rag_ingested", False),
            "analyst_summary": analysis.get("analyst_summary", ""),
            "full_analysis": analysis,
            "recommended_actions": analysis.get("recommended_actions", {}),
            "ioc_analysis": analysis.get("ioc_analysis", []),
            "investigation_queries": analysis.get("investigation_queries", {}),
        }

    async def _get_splunk_context(self, event_data: Dict) -> Dict:
        """Query Splunk MCP for historical context"""
        context = {
            "host_history": [],
            "user_history": [],
            "related_events": [],
            "similar_alerts": []
        }

        try:
            # Get host history
            host = event_data.get("host", "")
            if host:
                host_result = await splunk_mcp_server.execute_search(
                    f'index=security_events host="{host}" | head 20 | table _time event_type user src_ip command_line',
                    earliest="-7d"
                )
                context["host_history"] = host_result.get("results", [])

            # Get user activity
            user = event_data.get("user", "")
            if user:
                user_result = await splunk_mcp_server.execute_search(
                    f'index=security_events user="{user}" | head 20 | table _time event_type host src_ip',
                    earliest="-7d"
                )
                context["user_history"] = user_result.get("results", [])

            # Get related IP events
            src_ip = event_data.get("src_ip", "")
            if src_ip:
                ip_result = await splunk_mcp_server.execute_search(
                    f'index=security_events src_ip="{src_ip}" | head 20 | table _time event_type host user',
                    earliest="-7d"
                )
                context["related_events"] = ip_result.get("results", [])

            # Use natural language query for similar patterns
            event_type = event_data.get("event_type", "")
            if event_type:
                nl_result = await ask_splunk_natural(
                    f"Show me recent {event_type} events with similar characteristics"
                )
                context["similar_alerts"] = nl_result.get("results", [])[:10]

            context["status"] = "success"

        except Exception as e:
            log(f"Splunk context retrieval failed: {e}")
            context["status"] = "partial"
            context["error"] = str(e)

        return context

    def _rag_retrieve(self, event_data: Dict) -> Dict:
        """Retrieve organizational context from RAG vector store"""
        try:
            context = rag_engine.retrieve_context(event_data)
            log("RAG retrieval complete", {
                "rag_active": context.get("rag_active"),
                "total_results": context.get("total_results", 0)
            })
            return context
        except Exception as e:
            log(f"RAG retrieval failed: {e}")
            return {"rag_active": False, "error": str(e)}

    async def _enrich_iocs(self, event_data: Dict) -> Dict:
        """Enrich IOCs from threat intel APIs"""
        try:
            enrichment = await enrich_event_iocs(event_data)
            return enrichment
        except Exception as e:
            log(f"IOC enrichment failed: {e}")
            return {"error": str(e), "iocs_enriched": 0}

    async def _web_research(self, event_data: Dict) -> Dict:
        """Research event via web search"""
        try:
            # General event research
            event_research = await research_for_event_triage(event_data)

            # Search for specific patterns
            command_line = event_data.get("command_line", "")
            pattern_research = None
            if "-enc" in command_line.lower():
                pattern_research = await security_researcher.search_threat_intel(
                    "powershell encoded base64 command attack technique detection"
                )

            # Search for remediation
            event_type = event_data.get("event_type", "unknown")
            remediation = await search_remediation(
                f"{event_type} security incident response"
            )

            return {
                "event_research": event_research,
                "pattern_research": pattern_research,
                "remediation_guidance": remediation,
                "status": "success"
            }

        except Exception as e:
            log(f"Web research failed: {e}")
            return {"error": str(e), "status": "failed"}

    async def _llm_analyze(self, event_data: Dict, splunk_context: Dict,
                          threat_intel: Dict, web_research: Dict,
                          rag_context: Dict = None) -> Dict:
        """Analyze with LLM, including RAG organizational context"""
        prompt = COMPREHENSIVE_PROMPT.format(
            event_data=json.dumps(event_data, indent=2, default=str),
            splunk_context=json.dumps(splunk_context, indent=2, default=str),
            threat_intel=json.dumps(threat_intel, indent=2, default=str),
            web_research=json.dumps(web_research, indent=2, default=str),
            rag_context=json.dumps(rag_context or {}, indent=2, default=str),
        )

        try:
            if self.provider == "gemini":
                response = await self._call_gemini(prompt)
            elif self.provider == "anthropic":
                response = await self._call_claude(prompt)
            else:
                response = await self._call_openai(prompt)

            return self._extract_json(response)

        except Exception as e:
            log(f"LLM analysis failed: {e}")
            return self._rule_based_analyze(event_data, splunk_context, threat_intel, web_research)

    async def _call_gemini(self, prompt: str) -> str:
        """Call Gemini API"""
        log("Calling Gemini API...")

        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 16384
                    }
                }
            )

            if response.status_code == 200:
                data = response.json()
                candidates = data.get("candidates", [])
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
                raise Exception("No content in Gemini response")
            else:
                raise Exception(f"Gemini API error: {response.status_code}")

    async def _call_claude(self, prompt: str) -> str:
        """Call Claude API"""
        log("Calling Claude API...")

        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-3-5-sonnet-20241022",
                    "max_tokens": 8192,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )

            if response.status_code == 200:
                data = response.json()
                return data["content"][0]["text"]
            else:
                raise Exception(f"Claude API error: {response.status_code}")

    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        log("Calling OpenAI API...")

        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4-turbo-preview",
                    "messages": [
                        {"role": "system", "content": "You are an expert SOC analyst."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 8192
                }
            )

            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                raise Exception(f"OpenAI API error: {response.status_code}")

    def _extract_json(self, text: str) -> Dict:
        """Extract JSON from LLM response, handling truncated output."""
        import re

        # Try matching ```json ... ```
        json_match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Strip markdown fences if present
        stripped = text.strip()
        if stripped.startswith('```'):
            stripped = re.sub(r'^```(?:json)?\s*', '', stripped)
            stripped = re.sub(r'\s*```\s*$', '', stripped)

        # Try direct parse
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

        # Truncated JSON: walk backwards closing open braces/brackets
        # Find the start of the JSON object
        start = stripped.find('{')
        if start < 0:
            return {"raw_response": text, "parse_error": True}

        candidate = stripped[start:]
        # Try progressively shorter substrings ending at each '}'
        last = len(candidate)
        while last > 0:
            last = candidate.rfind('}', 0, last)
            if last < 0:
                break
            try:
                return json.loads(candidate[:last + 1])
            except json.JSONDecodeError:
                continue

        return {"raw_response": text, "parse_error": True}

    def _rule_based_analyze(self, event_data: Dict, splunk_context: Dict,
                           threat_intel: Dict, web_research: Dict) -> Dict:
        """Fallback rule-based analysis"""
        log("Using rule-based analysis (LLM not configured)")

        overall_risk = threat_intel.get("overall_risk", "unknown")
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        severity = severity_map.get(overall_risk, "medium")
        command_line = event_data.get("command_line", "").lower()
        if "-enc" in command_line and "powershell" in command_line:
            classification = "true_positive"
            confidence = 85
        elif any(term in command_line for term in ["invoke-", "downloadstring", "webclient"]):
            classification = "true_positive"
            confidence = 75
        else:
            classification = "needs_investigation"
            confidence = 50

        return {
            "classification": classification,
            "confidence": confidence,
            "severity": severity,
            "severity_justification": "Rule-based assessment",
            "mitre_attack": {
                "techniques": [{"id": "T1059.001", "name": "PowerShell", "evidence": "Command line analysis"}],
                "tactics": ["Execution"],
                "kill_chain_phase": "Execution"
            },
            "threat_attribution": {
                "threat_actors": [],
                "malware_families": [],
                "campaigns": []
            },
            "recommended_actions": {
                "immediate": [{"action": "Investigate event", "reason": "Rule-based detection"}],
                "short_term": [{"action": "Review host activity", "reason": "Determine scope"}],
                "long_term": [{"action": "Configure LLM for AI analysis", "reason": "Improved detection"}]
            },
            "investigation_queries": {
                "spl": [f'index=security_events host="{event_data.get("host", "*")}"'],
                "natural_language": ["Show me similar events from this host"]
            },
            "analyst_summary": "Rule-based analysis. Configure GEMINI_API_KEY for comprehensive AI analysis.",
            "llm_enabled": False
        }

    async def _validate_findings(self, analysis: Dict, event_data: Dict) -> Dict:
        """Validate key findings with web research"""
        if analysis.get("parse_error") or analysis.get("raw_response"):
            return analysis

        try:
            # Validate classification
            classification = analysis.get("classification", "")
            event_type = event_data.get("event_type", "")

            if classification == "true_positive":
                validation = await validate_finding(
                    f"{event_type} is a malicious security event",
                    event_data.get("command_line", "")[:100]
                )
                analysis["classification_validation"] = {
                    "validated": validation.get("validation_confidence", 0) > 50,
                    "confidence": validation.get("validation_confidence", 0),
                    "sources": validation.get("supporting_sources", [])[:3]
                }

            # Validate MITRE techniques
            techniques = analysis.get("mitre_attack", {}).get("techniques", [])
            for technique in techniques[:2]:  # Validate first 2
                if isinstance(technique, dict) and technique.get("id"):
                    tech_validation = await validate_finding(
                        f"{technique['id']} {technique.get('name', '')}",
                        event_type
                    )
                    technique["validation"] = {
                        "confidence": tech_validation.get("validation_confidence", 0)
                    }

        except Exception as e:
            log(f"Validation failed: {e}")
            analysis["validation_error"] = str(e)

        return analysis


comprehensive_analyzer = ComprehensiveAnalyzer()


async def full_investigation(event_data: Dict) -> Dict:
    """Run comprehensive investigation"""
    return await comprehensive_analyzer.full_investigation(event_data)


async def investigate_alert(event_data: Dict) -> Dict:
    """Alias for full_investigation"""
    return await comprehensive_analyzer.full_investigation(event_data)
