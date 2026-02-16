"""
LLM Security Analyzer
Sends structured prompts to Gemini/Claude/OpenAI for alert triage and classification.
"""
import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx

# Configuration - Set your API key in .env
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# LLM Provider selection
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")  # "anthropic", "openai", or "gemini"


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [LLM-ANALYZER] {msg}")
    if data:
        print(f"  -> {data}")


# SOC Analysis Prompt Template
SOC_ANALYSIS_PROMPT = """You are an expert SOC (Security Operations Center) analyst. Analyze the following security event and provide a detailed investigation report.

## Security Event Data
```json
{event_data}
```

## Your Analysis Tasks
1. **Classification**: Is this a True Positive, False Positive, or Benign True Positive?
2. **Severity Assessment**: Rate severity (Critical/High/Medium/Low) with justification
3. **MITRE ATT&CK Mapping**: Identify relevant techniques and tactics
4. **Threat Intelligence**: What threat actors or malware families might be involved?
5. **Attack Chain Analysis**: Where does this fit in a potential attack chain?
6. **Indicators of Compromise (IOCs)**: Extract all IOCs (IPs, domains, hashes, etc.)
7. **Recommended Actions**: What immediate and long-term actions should be taken?
8. **Investigation Queries**: Suggest Splunk SPL queries for further investigation

## Response Format
Provide your analysis in the following JSON structure:
```json
{{
    "classification": "true_positive|false_positive|benign_true_positive",
    "confidence": 0-100,
    "severity": "critical|high|medium|low",
    "severity_justification": "...",
    "mitre_attack": {{
        "techniques": ["T1XXX - Name"],
        "tactics": ["Tactic Name"],
        "kill_chain_phase": "..."
    }},
    "threat_intelligence": {{
        "potential_threat_actors": [],
        "malware_families": [],
        "campaign_names": []
    }},
    "iocs": {{
        "ip_addresses": [],
        "domains": [],
        "file_hashes": [],
        "file_paths": [],
        "registry_keys": []
    }},
    "recommended_actions": {{
        "immediate": [],
        "short_term": [],
        "long_term": []
    }},
    "investigation_queries": [],
    "analyst_notes": "..."
}}
```
"""

THREAT_INTEL_PROMPT = """You are a threat intelligence analyst. Analyze the following indicator and provide threat intelligence assessment.

## Indicator
Type: {indicator_type}
Value: {indicator_value}

## Analysis Required
1. Is this indicator known to be malicious?
2. What threat actors or campaigns are associated with it?
3. What is the confidence level?
4. What additional context can you provide?

Respond in JSON format:
```json
{{
    "indicator": "{indicator_value}",
    "verdict": "malicious|suspicious|clean|unknown",
    "confidence": 0-100,
    "threat_actors": [],
    "campaigns": [],
    "first_seen": "date or unknown",
    "tags": [],
    "context": "...",
    "references": []
}}
```
"""


class LLMAnalyzer:
    """LLM-powered security analysis"""

    def __init__(self):
        self.provider = LLM_PROVIDER

        # Select API key based on provider
        if self.provider == "gemini":
            self.api_key = GEMINI_API_KEY
        elif self.provider == "anthropic":
            self.api_key = ANTHROPIC_API_KEY
        else:
            self.api_key = OPENAI_API_KEY

        if not self.api_key:
            log("WARNING: No API key configured. Set GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY in .env")
            self.enabled = False
        else:
            self.enabled = True
            log(f"LLM Analyzer initialized with provider: {self.provider}")

    async def analyze_event(self, event_data: Dict) -> Dict:
        """Analyze security event using LLM"""
        if not self.enabled:
            return self._fallback_analysis(event_data)

        prompt = SOC_ANALYSIS_PROMPT.format(
            event_data=json.dumps(event_data, indent=2, default=str)
        )

        try:
            if self.provider == "gemini":
                response = await self._call_gemini(prompt)
            elif self.provider == "anthropic":
                response = await self._call_claude(prompt)
            else:
                response = await self._call_openai(prompt)

            # Parse JSON from response
            analysis = self._extract_json(response)
            analysis["llm_provider"] = self.provider
            analysis["timestamp"] = datetime.now().isoformat()

            log("LLM analysis complete", {"severity": analysis.get("severity")})
            return analysis

        except Exception as e:
            log(f"LLM analysis failed: {e}")
            return self._fallback_analysis(event_data)

    async def lookup_threat_intel(self, indicator: str, indicator_type: str = "auto") -> Dict:
        """Look up threat intelligence for an indicator using LLM"""
        if not self.enabled:
            return {"indicator": indicator, "verdict": "unknown", "note": "LLM not configured"}

        # Auto-detect indicator type
        if indicator_type == "auto":
            if self._is_ip(indicator):
                indicator_type = "IP Address"
            elif self._is_domain(indicator):
                indicator_type = "Domain"
            elif self._is_hash(indicator):
                indicator_type = "File Hash"
            else:
                indicator_type = "Unknown"

        prompt = THREAT_INTEL_PROMPT.format(
            indicator_type=indicator_type,
            indicator_value=indicator
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
            log(f"Threat intel lookup failed: {e}")
            return {"indicator": indicator, "verdict": "unknown", "error": str(e)}

    async def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API"""
        log("Calling Google Gemini API...")

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [
                        {
                            "parts": [
                                {"text": prompt}
                            ]
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 8192
                    }
                }
            )

            if response.status_code == 200:
                data = response.json()
                # Extract text from Gemini response
                candidates = data.get("candidates", [])
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
                raise Exception("No content in Gemini response")
            else:
                raise Exception(f"Gemini API error: {response.status_code} - {response.text}")

    async def _call_claude(self, prompt: str) -> str:
        """Call Claude API"""
        log("Calling Claude API...")

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-3-5-sonnet-20241022",
                    "max_tokens": 4096,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ]
                }
            )

            if response.status_code == 200:
                data = response.json()
                return data["content"][0]["text"]
            else:
                raise Exception(f"Claude API error: {response.status_code} - {response.text}")

    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        log("Calling OpenAI API...")

        async with httpx.AsyncClient(timeout=60.0) as client:
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
                    "max_tokens": 4096
                }
            )

            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")

    def _extract_json(self, text: str) -> Dict:
        """Extract JSON from LLM response"""
        import re
        # Find JSON block in response
        json_match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))

        # Try to parse entire response as JSON
        try:
            return json.loads(text)
        except:
            return {"raw_response": text, "parse_error": True}

    def _fallback_analysis(self, event_data: Dict) -> Dict:
        """Fallback rule-based analysis when LLM is not available"""
        log("Using fallback rule-based analysis (no LLM configured)")

        event_type = event_data.get("event_type", "unknown")

        # Basic rule-based analysis
        severity = "medium"
        classification = "needs_investigation"

        if event_type == "lateral_movement":
            severity = "high"
        elif event_type == "data_exfiltration":
            severity = "critical"
        elif "enc" in str(event_data.get("command_line", "")).lower():
            severity = "high"

        return {
            "classification": classification,
            "confidence": 50,
            "severity": severity,
            "severity_justification": "Rule-based assessment - LLM not configured",
            "mitre_attack": {"techniques": [], "tactics": []},
            "threat_intelligence": {"potential_threat_actors": [], "note": "Configure LLM for detailed analysis"},
            "iocs": self._extract_iocs(event_data),
            "recommended_actions": {
                "immediate": ["Review event details", "Check for related alerts"],
                "short_term": ["Investigate affected systems"],
                "long_term": ["Configure LLM API for automated analysis"]
            },
            "investigation_queries": [
                f'index=security_events host="{event_data.get("host", "*")}"',
                f'index=security_events src_ip="{event_data.get("src_ip", "*")}"'
            ],
            "analyst_notes": "Rule-based analysis only. Set GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY in .env for full analysis.",
            "llm_enabled": False
        }

    def _extract_iocs(self, event_data: Dict) -> Dict:
        """Extract IOCs from event data"""
        iocs = {"ip_addresses": [], "domains": [], "file_hashes": [], "file_paths": []}

        for key in ["src_ip", "dest_ip", "client_ip"]:
            if event_data.get(key):
                iocs["ip_addresses"].append(event_data[key])

        if event_data.get("query"):
            iocs["domains"].append(event_data["query"])
        if event_data.get("file_hash"):
            iocs["file_hashes"].append(event_data["file_hash"])
        if event_data.get("file_path"):
            iocs["file_paths"].append(event_data["file_path"])

        return {k: v for k, v in iocs.items() if v}

    def _is_ip(self, s: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))

    def _is_domain(self, s: str) -> bool:
        return '.' in s and not self._is_ip(s) and not self._is_hash(s)

    def _is_hash(self, s: str) -> bool:
        import re
        return bool(re.match(r'^[a-fA-F0-9]{32,64}$', s))


# Singleton instance
llm_analyzer = LLMAnalyzer()


# Convenience functions
async def analyze_security_event(event_data: Dict) -> Dict:
    """Analyze a security event using LLM"""
    return await llm_analyzer.analyze_event(event_data)


async def get_threat_intel(indicator: str) -> Dict:
    """Get threat intelligence for an indicator"""
    return await llm_analyzer.lookup_threat_intel(indicator)
