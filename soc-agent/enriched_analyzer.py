"""
Enriched Analyzer
Combines IOC threat intel enrichment with LLM analysis for deeper triage.
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx

from web_enrichment import threat_intel, enrich_event_iocs, enrich_ioc
from mcp_client import splunk_mcp, search_splunk

# Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [ENRICHED-ANALYZER] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:500]}")


# Enhanced SOC Analysis Prompt with Enrichment Data
ENRICHED_ANALYSIS_PROMPT = """You are an expert SOC (Security Operations Center) analyst. Analyze the following security event along with the threat intelligence enrichment data and provide a detailed investigation report.

## Security Event Data
```json
{event_data}
```

## Threat Intelligence Enrichment
The following IOCs were extracted and enriched from external threat intelligence sources:
```json
{enrichment_data}
```

## Historical Context (from Splunk)
```json
{historical_context}
```

## Your Analysis Tasks
1. **Classification**: Based on the event AND enrichment data, is this a True Positive, False Positive, or Benign True Positive?
2. **Confidence Level**: How confident are you in this classification (0-100)? Justify based on enrichment data.
3. **Severity Assessment**: Rate severity (Critical/High/Medium/Low) considering the threat intel
4. **MITRE ATT&CK Mapping**: Identify relevant techniques and tactics
5. **Threat Attribution**: Based on enrichment, what threat actors or malware families might be involved?
6. **IOC Analysis**: Summarize the enrichment findings for each IOC
7. **Attack Chain Position**: Where does this fit in a potential attack chain?
8. **Recommended Actions**: What immediate and long-term actions should be taken?
9. **Investigation Queries**: Suggest Splunk SPL queries for further investigation
10. **Verdict Justification**: Explain why you reached this verdict, citing enrichment sources

## Response Format
Provide your analysis in the following JSON structure:
```json
{{
    "classification": "true_positive|false_positive|benign_true_positive",
    "confidence": 0-100,
    "confidence_justification": "Based on enrichment from...",
    "severity": "critical|high|medium|low",
    "severity_justification": "...",
    "mitre_attack": {{
        "techniques": ["T1XXX - Name"],
        "tactics": ["Tactic Name"],
        "kill_chain_phase": "..."
    }},
    "threat_attribution": {{
        "threat_actors": [],
        "malware_families": [],
        "campaigns": [],
        "attribution_confidence": "high|medium|low"
    }},
    "ioc_summary": {{
        "malicious_iocs": [],
        "suspicious_iocs": [],
        "clean_iocs": []
    }},
    "enrichment_highlights": [
        "VirusTotal: IP x.x.x.x flagged by N engines",
        "AbuseIPDB: Abuse confidence score of N%"
    ],
    "recommended_actions": {{
        "immediate": [],
        "short_term": [],
        "long_term": []
    }},
    "investigation_queries": [],
    "verdict_justification": "...",
    "analyst_notes": "..."
}}
```
"""

TRIAGE_DECISION_PROMPT = """Based on the security event and threat intelligence enrichment, make a quick triage decision.

## Event Summary
{event_summary}

## Enrichment Summary
{enrichment_summary}

Respond with ONLY a JSON object:
```json
{{
    "triage_decision": "escalate|investigate|monitor|close",
    "priority": "P1|P2|P3|P4",
    "confidence": 0-100,
    "reason": "brief explanation",
    "recommended_analyst_tier": "Tier1|Tier2|Tier3|SOC_Lead"
}}
```
"""


class EnrichedAnalyzer:
    """
    Combines web-based threat intelligence enrichment with LLM analysis
    for comprehensive, evidence-based alert triage.
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
        log(f"Enriched Analyzer initialized", {
            "provider": self.provider,
            "enabled": self.enabled
        })

    async def analyze_and_enrich(self, event_data: Dict) -> Dict:
        """
        Full analysis pipeline:
        1. Enrich IOCs from web sources
        2. Get historical context from Splunk
        3. Analyze with LLM
        4. Return comprehensive report
        """
        log("Starting enriched analysis", {"event_type": event_data.get("event_type")})

        # Step 1: Enrich IOCs from web sources
        log("Step 1: Enriching IOCs from web sources...")
        enrichment_data = await self._enrich_iocs(event_data)

        # Step 2: Get historical context from Splunk
        log("Step 2: Getting historical context from Splunk...")
        historical_context = await self._get_historical_context(event_data)

        # Step 3: Analyze with LLM
        log("Step 3: Analyzing with LLM...")
        if self.enabled:
            analysis = await self._llm_analyze(event_data, enrichment_data, historical_context)
        else:
            analysis = self._rule_based_analyze(event_data, enrichment_data)

        # Step 4: Combine everything into final report
        report = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "event_data": event_data,
            "enrichment": enrichment_data,
            "historical_context": historical_context,
            "analysis": analysis,
            "llm_provider": self.provider if self.enabled else "rule_based"
        }

        log("Enriched analysis complete", {
            "classification": analysis.get("classification"),
            "severity": analysis.get("severity"),
            "iocs_enriched": enrichment_data.get("iocs_enriched", 0)
        })

        return report

    async def quick_triage(self, event_data: Dict) -> Dict:
        """Quick triage decision without full analysis"""
        log("Performing quick triage")

        # Quick enrichment of key IOCs
        enrichment = await self._enrich_iocs(event_data)

        # Build summary for quick decision
        event_summary = self._build_event_summary(event_data)
        enrichment_summary = self._build_enrichment_summary(enrichment)

        if self.enabled:
            decision = await self._llm_quick_triage(event_summary, enrichment_summary)
        else:
            decision = self._rule_based_triage(event_data, enrichment)

        return {
            "timestamp": datetime.now().isoformat(),
            "event_id": event_data.get("event_id", "unknown"),
            "triage": decision,
            "enrichment_summary": enrichment_summary
        }

    async def _enrich_iocs(self, event_data: Dict) -> Dict:
        """Enrich IOCs from the event"""
        try:
            enrichment = await enrich_event_iocs(event_data)
            return enrichment
        except Exception as e:
            log(f"IOC enrichment failed: {e}")
            return {"error": str(e), "iocs_enriched": 0}

    async def _get_historical_context(self, event_data: Dict) -> Dict:
        """Get historical context from Splunk"""
        context = {
            "related_events": [],
            "user_history": [],
            "host_history": []
        }

        try:
            # Get related events for the host
            host = event_data.get("host", "")
            if host:
                host_query = f'search index=security_events host="{host}" | head 10 | table _time event_type user src_ip'
                host_result = await search_splunk(host_query, earliest="-7d")
                context["host_history"] = host_result.get("results", [])

            # Get user activity
            user = event_data.get("user", "")
            if user:
                user_query = f'search index=security_events user="{user}" | head 10 | table _time event_type host src_ip'
                user_result = await search_splunk(user_query, earliest="-7d")
                context["user_history"] = user_result.get("results", [])

            # Get related source IP events
            src_ip = event_data.get("src_ip", "")
            if src_ip:
                ip_query = f'search index=security_events src_ip="{src_ip}" | head 10 | table _time event_type host user'
                ip_result = await search_splunk(ip_query, earliest="-7d")
                context["related_events"] = ip_result.get("results", [])

        except Exception as e:
            log(f"Historical context retrieval failed: {e}")
            context["error"] = str(e)

        return context

    async def _llm_analyze(self, event_data: Dict, enrichment: Dict, history: Dict) -> Dict:
        """Analyze with LLM"""
        prompt = ENRICHED_ANALYSIS_PROMPT.format(
            event_data=json.dumps(event_data, indent=2, default=str),
            enrichment_data=json.dumps(enrichment, indent=2, default=str),
            historical_context=json.dumps(history, indent=2, default=str)
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
            return self._rule_based_analyze(event_data, enrichment)

    async def _llm_quick_triage(self, event_summary: str, enrichment_summary: str) -> Dict:
        """Quick triage with LLM"""
        prompt = TRIAGE_DECISION_PROMPT.format(
            event_summary=event_summary,
            enrichment_summary=enrichment_summary
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
            log(f"Quick triage LLM call failed: {e}")
            return {"triage_decision": "investigate", "priority": "P2", "confidence": 50}

    async def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API"""
        log("Calling Gemini API...")

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 8192
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

        async with httpx.AsyncClient(timeout=120.0) as client:
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

        async with httpx.AsyncClient(timeout=120.0) as client:
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
        """Extract JSON from LLM response"""
        import re

        json_match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        try:
            return json.loads(text)
        except:
            return {"raw_response": text, "parse_error": True}

    def _rule_based_analyze(self, event_data: Dict, enrichment: Dict) -> Dict:
        """Fallback rule-based analysis when LLM is not available"""
        log("Using rule-based analysis (LLM not configured)")

        # Determine severity based on enrichment
        overall_risk = enrichment.get("overall_risk", "unknown")

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low"
        }
        severity = severity_map.get(overall_risk, "medium")

        # Check for malicious IOCs
        malicious_iocs = []
        suspicious_iocs = []
        clean_iocs = []

        for e in enrichment.get("enrichments", []):
            verdict = e.get("verdict", "unknown")
            indicator = e.get("indicator", "unknown")
            if verdict == "malicious":
                malicious_iocs.append(indicator)
            elif verdict == "suspicious":
                suspicious_iocs.append(indicator)
            elif verdict in ["clean", "benign"]:
                clean_iocs.append(indicator)

        # Determine classification
        if malicious_iocs:
            classification = "true_positive"
            confidence = 85
        elif suspicious_iocs:
            classification = "needs_investigation"
            confidence = 60
        else:
            classification = "likely_benign"
            confidence = 50

        return {
            "classification": classification,
            "confidence": confidence,
            "confidence_justification": f"Based on {len(malicious_iocs)} malicious and {len(suspicious_iocs)} suspicious IOCs",
            "severity": severity,
            "severity_justification": f"Overall risk score: {overall_risk}",
            "mitre_attack": self._guess_mitre(event_data),
            "threat_attribution": {
                "threat_actors": [],
                "malware_families": [],
                "campaigns": [],
                "attribution_confidence": "low"
            },
            "ioc_summary": {
                "malicious_iocs": malicious_iocs,
                "suspicious_iocs": suspicious_iocs,
                "clean_iocs": clean_iocs
            },
            "enrichment_highlights": self._build_enrichment_highlights(enrichment),
            "recommended_actions": self._get_recommended_actions(severity),
            "investigation_queries": self._generate_queries(event_data),
            "verdict_justification": f"Rule-based analysis. Found {len(malicious_iocs)} malicious IOCs.",
            "analyst_notes": "LLM not configured. Set GEMINI_API_KEY in .env to enable automated analysis.",
            "llm_enabled": False
        }

    def _rule_based_triage(self, event_data: Dict, enrichment: Dict) -> Dict:
        """Rule-based quick triage"""
        risk = enrichment.get("overall_risk", "unknown")

        decision_map = {
            "critical": ("escalate", "P1", "Tier3"),
            "high": ("escalate", "P2", "Tier2"),
            "medium": ("investigate", "P3", "Tier1"),
            "low": ("monitor", "P4", "Tier1"),
            "informational": ("close", "P4", "Tier1")
        }

        decision, priority, tier = decision_map.get(risk, ("investigate", "P3", "Tier1"))

        return {
            "triage_decision": decision,
            "priority": priority,
            "confidence": 60,
            "reason": f"Rule-based triage. Risk level: {risk}",
            "recommended_analyst_tier": tier
        }

    def _build_event_summary(self, event_data: Dict) -> str:
        """Build concise event summary"""
        parts = []
        if event_data.get("event_type"):
            parts.append(f"Type: {event_data['event_type']}")
        if event_data.get("host"):
            parts.append(f"Host: {event_data['host']}")
        if event_data.get("user"):
            parts.append(f"User: {event_data['user']}")
        if event_data.get("src_ip"):
            parts.append(f"Source IP: {event_data['src_ip']}")
        if event_data.get("command_line"):
            parts.append(f"Command: {event_data['command_line'][:100]}...")
        return " | ".join(parts)

    def _build_enrichment_summary(self, enrichment: Dict) -> str:
        """Build concise enrichment summary"""
        parts = [f"IOCs enriched: {enrichment.get('iocs_enriched', 0)}"]
        parts.append(f"Overall risk: {enrichment.get('overall_risk', 'unknown')}")

        for e in enrichment.get("enrichments", [])[:3]:
            source = e.get("sources", [{}])[0].get("source", "unknown") if e.get("sources") else "unknown"
            verdict = e.get("verdict", "unknown")
            parts.append(f"{e.get('indicator', 'unknown')[:20]}: {verdict} ({source})")

        return " | ".join(parts)

    def _build_enrichment_highlights(self, enrichment: Dict) -> List[str]:
        """Build list of enrichment highlights"""
        highlights = []

        for e in enrichment.get("enrichments", []):
            for source in e.get("sources", []):
                source_name = source.get("source", "unknown")
                verdict = source.get("verdict", "unknown")
                indicator = source.get("indicator", "unknown")

                if verdict == "malicious":
                    if source.get("malicious"):
                        highlights.append(f"{source_name}: {indicator} flagged by {source['malicious']} engines")
                    if source.get("abuse_confidence_score"):
                        highlights.append(f"{source_name}: {indicator} has {source['abuse_confidence_score']}% abuse score")

        return highlights[:10]  # Top 10 highlights

    def _guess_mitre(self, event_data: Dict) -> Dict:
        """Guess MITRE techniques from event data"""
        techniques = []
        tactics = []

        event_type = event_data.get("event_type", "")
        command_line = event_data.get("command_line", "").lower()

        if "powershell" in command_line or event_type == "process_creation":
            if "-enc" in command_line or "-encoded" in command_line:
                techniques.append("T1059.001 - PowerShell")
                techniques.append("T1027 - Obfuscated Files or Information")
                tactics.extend(["Execution", "Defense Evasion"])

        if event_type == "brute_force" or "failed" in event_type.lower():
            techniques.append("T1110 - Brute Force")
            tactics.append("Credential Access")

        if event_type == "lateral_movement":
            techniques.append("T1021 - Remote Services")
            tactics.append("Lateral Movement")

        if event_type == "data_exfiltration":
            techniques.append("T1048 - Exfiltration Over Alternative Protocol")
            tactics.append("Exfiltration")

        return {
            "techniques": techniques or ["Unknown"],
            "tactics": tactics or ["Unknown"],
            "kill_chain_phase": "Unknown"
        }

    def _get_recommended_actions(self, severity: str) -> Dict:
        """Get recommended actions based on severity"""
        actions = {
            "critical": {
                "immediate": ["Isolate affected systems", "Notify incident response team", "Preserve evidence"],
                "short_term": ["Full forensic analysis", "Review all related alerts", "Check for lateral movement"],
                "long_term": ["Update detection rules", "Conduct lessons learned", "Implement additional controls"]
            },
            "high": {
                "immediate": ["Investigate within 1 hour", "Check for active threats"],
                "short_term": ["Review user/host history", "Correlate with other alerts"],
                "long_term": ["Tune detection rules", "User security training"]
            },
            "medium": {
                "immediate": ["Investigate within 4 hours"],
                "short_term": ["Correlate events", "Check IOC reputation"],
                "long_term": ["Monitor for recurrence"]
            },
            "low": {
                "immediate": ["Document and monitor"],
                "short_term": ["Add to trending analysis"],
                "long_term": ["Review in weekly meeting"]
            }
        }
        return actions.get(severity, actions["medium"])

    def _generate_queries(self, event_data: Dict) -> List[str]:
        """Generate Splunk investigation queries"""
        queries = []

        host = event_data.get("host", "*")
        user = event_data.get("user", "*")
        src_ip = event_data.get("src_ip", "*")

        queries.append(f'index=security_events host="{host}" | table _time event_type user src_ip command_line')
        queries.append(f'index=security_events user="{user}" | stats count by event_type, host')
        queries.append(f'index=security_events src_ip="{src_ip}" | stats count by host, user, event_type')
        queries.append(f'index=security_events host="{host}" event_type=process_creation | table _time process command_line')

        return queries


# Singleton instance
enriched_analyzer = EnrichedAnalyzer()


# Convenience functions
async def analyze_with_enrichment(event_data: Dict) -> Dict:
    """Full analysis with web enrichment and LLM"""
    return await enriched_analyzer.analyze_and_enrich(event_data)


async def quick_triage(event_data: Dict) -> Dict:
    """Quick triage decision"""
    return await enriched_analyzer.quick_triage(event_data)
