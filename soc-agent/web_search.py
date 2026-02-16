"""
Web Search Module
Searches for IOC reputation, CVE details, MITRE techniques, and remediation steps.
Supports Serper, Google CSE, and DuckDuckGo backends.
"""
import os
import json
import asyncio
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import quote_plus, urljoin
import httpx

# API Keys (optional - some searches work without keys)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID", "")
SERPER_API_KEY = os.getenv("SERPER_API_KEY", "")  # serper.dev - Google search API


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [WEB-SEARCH] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:400]}")


class WebSearchEngine:
    """
    Multi-source web search for security research.
    Uses DuckDuckGo (free), Serper (Google), or direct API calls.
    """

    def __init__(self):
        self.serper_key = SERPER_API_KEY
        self.google_key = GOOGLE_API_KEY
        self.google_cse = GOOGLE_CSE_ID

        # Determine best available search method
        if self.serper_key:
            self.primary_engine = "serper"
        elif self.google_key and self.google_cse:
            self.primary_engine = "google"
        else:
            self.primary_engine = "duckduckgo"

        log(f"Web Search initialized with engine: {self.primary_engine}")

    async def search(self, query: str, num_results: int = 10) -> Dict:
        """General web search"""
        log(f"Searching: {query[:50]}...")

        if self.primary_engine == "serper":
            return await self._search_serper(query, num_results)
        elif self.primary_engine == "google":
            return await self._search_google(query, num_results)
        else:
            return await self._search_duckduckgo(query, num_results)

    async def _search_serper(self, query: str, num_results: int) -> Dict:
        """Search using Serper.dev (Google Search API)"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    "https://google.serper.dev/search",
                    headers={
                        "X-API-KEY": self.serper_key,
                        "Content-Type": "application/json"
                    },
                    json={
                        "q": query,
                        "num": num_results
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    results = []

                    for item in data.get("organic", []):
                        results.append({
                            "title": item.get("title"),
                            "url": item.get("link"),
                            "snippet": item.get("snippet"),
                            "source": "serper"
                        })

                    return {
                        "query": query,
                        "engine": "serper",
                        "result_count": len(results),
                        "results": results
                    }
                else:
                    raise Exception(f"Serper API error: {response.status_code}")

            except Exception as e:
                log(f"Serper search failed: {e}")
                # Fallback to DuckDuckGo
                return await self._search_duckduckgo(query, num_results)

    async def _search_google(self, query: str, num_results: int) -> Dict:
        """Search using Google Custom Search API"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={
                        "key": self.google_key,
                        "cx": self.google_cse,
                        "q": query,
                        "num": min(num_results, 10)
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    results = []

                    for item in data.get("items", []):
                        results.append({
                            "title": item.get("title"),
                            "url": item.get("link"),
                            "snippet": item.get("snippet"),
                            "source": "google"
                        })

                    return {
                        "query": query,
                        "engine": "google",
                        "result_count": len(results),
                        "results": results
                    }
                else:
                    raise Exception(f"Google API error: {response.status_code}")

            except Exception as e:
                log(f"Google search failed: {e}")
                return await self._search_duckduckgo(query, num_results)

    async def _search_duckduckgo(self, query: str, num_results: int) -> Dict:
        """Search using DuckDuckGo (free, no API key)"""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                # DuckDuckGo Instant Answer API
                response = await client.get(
                    "https://api.duckduckgo.com/",
                    params={
                        "q": query,
                        "format": "json",
                        "no_html": 1,
                        "skip_disambig": 1
                    }
                )

                results = []

                if response.status_code == 200:
                    data = response.json()

                    # Abstract (main answer)
                    if data.get("Abstract"):
                        results.append({
                            "title": data.get("Heading", "DuckDuckGo Answer"),
                            "url": data.get("AbstractURL", ""),
                            "snippet": data.get("Abstract"),
                            "source": "duckduckgo_instant"
                        })

                    # Related topics
                    for topic in data.get("RelatedTopics", [])[:num_results-1]:
                        if isinstance(topic, dict) and topic.get("Text"):
                            results.append({
                                "title": topic.get("Text", "")[:100],
                                "url": topic.get("FirstURL", ""),
                                "snippet": topic.get("Text", ""),
                                "source": "duckduckgo_related"
                            })

                # If no results from instant API, try HTML scraping approach
                if not results:
                    results = await self._scrape_duckduckgo_html(client, query, num_results)

                return {
                    "query": query,
                    "engine": "duckduckgo",
                    "result_count": len(results),
                    "results": results
                }

            except Exception as e:
                log(f"DuckDuckGo search failed: {e}")
                return {
                    "query": query,
                    "engine": "duckduckgo",
                    "error": str(e),
                    "results": []
                }

    async def _scrape_duckduckgo_html(self, client: httpx.AsyncClient, query: str, num_results: int) -> List[Dict]:
        """Fallback: scrape DuckDuckGo HTML results"""
        try:
            response = await client.get(
                f"https://html.duckduckgo.com/html/?q={quote_plus(query)}",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            )

            results = []
            if response.status_code == 200:
                html = response.text

                # Simple regex extraction (basic but works)
                links = re.findall(r'<a rel="nofollow" class="result__a" href="([^"]+)">([^<]+)</a>', html)
                snippets = re.findall(r'<a class="result__snippet"[^>]*>([^<]+)</a>', html)

                for i, (url, title) in enumerate(links[:num_results]):
                    snippet = snippets[i] if i < len(snippets) else ""
                    # Decode DuckDuckGo redirect URL
                    if "uddg=" in url:
                        url_match = re.search(r'uddg=([^&]+)', url)
                        if url_match:
                            from urllib.parse import unquote
                            url = unquote(url_match.group(1))

                    results.append({
                        "title": title.strip(),
                        "url": url,
                        "snippet": snippet.strip(),
                        "source": "duckduckgo_html"
                    })

            return results

        except Exception as e:
            log(f"DuckDuckGo HTML scraping failed: {e}")
            return []


class SecurityResearcher:
    """
    Specialized security research using web search.
    Searches security-specific sources for threat intel, CVEs, MITRE, etc.
    """

    def __init__(self):
        self.search_engine = WebSearchEngine()
        self.security_sites = [
            "site:attack.mitre.org",
            "site:nvd.nist.gov",
            "site:cve.mitre.org",
            "site:virustotal.com",
            "site:malwarebazaar.abuse.ch",
            "site:threatpost.com",
            "site:bleepingcomputer.com",
            "site:thehackernews.com",
            "site:krebsonsecurity.com",
            "site:reddit.com/r/netsec",
            "site:security.stackexchange.com"
        ]

    async def research_ioc(self, indicator: str, indicator_type: str = "auto") -> Dict:
        """Research an IOC (IP, domain, hash) using web search"""
        log(f"Researching IOC: {indicator}")

        # Detect type if auto
        if indicator_type == "auto":
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
                indicator_type = "ip"
            elif re.match(r'^[a-fA-F0-9]{32,64}$', indicator):
                indicator_type = "hash"
            elif "." in indicator:
                indicator_type = "domain"
            else:
                indicator_type = "unknown"

        # Build search queries
        queries = [
            f'"{indicator}" malware threat',
            f'"{indicator}" security incident',
            f'"{indicator}" site:virustotal.com OR site:abuseipdb.com OR site:threatcrowd.org'
        ]

        all_results = []
        for query in queries:
            result = await self.search_engine.search(query, num_results=5)
            all_results.extend(result.get("results", []))

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for r in all_results:
            if r.get("url") not in seen_urls:
                seen_urls.add(r.get("url"))
                unique_results.append(r)

        return {
            "indicator": indicator,
            "type": indicator_type,
            "research_results": unique_results[:10],
            "sources_searched": len(queries),
            "timestamp": datetime.now().isoformat()
        }

    async def research_mitre_technique(self, technique_id: str) -> Dict:
        """Research MITRE ATT&CK technique"""
        log(f"Researching MITRE technique: {technique_id}")

        queries = [
            f'site:attack.mitre.org {technique_id}',
            f'{technique_id} detection defense mitigation',
            f'{technique_id} attack technique examples'
        ]

        all_results = []
        for query in queries:
            result = await self.search_engine.search(query, num_results=5)
            all_results.extend(result.get("results", []))

        return {
            "technique_id": technique_id,
            "research_results": all_results[:10],
            "timestamp": datetime.now().isoformat()
        }

    async def research_cve(self, cve_id: str) -> Dict:
        """Research CVE vulnerability"""
        log(f"Researching CVE: {cve_id}")

        queries = [
            f'site:nvd.nist.gov {cve_id}',
            f'{cve_id} exploit poc',
            f'{cve_id} patch mitigation remediation'
        ]

        all_results = []
        for query in queries:
            result = await self.search_engine.search(query, num_results=5)
            all_results.extend(result.get("results", []))

        return {
            "cve_id": cve_id,
            "research_results": all_results[:10],
            "timestamp": datetime.now().isoformat()
        }

    async def search_threat_intel(self, query: str) -> Dict:
        """General threat intelligence search"""
        log(f"Threat intel search: {query[:50]}")

        # Add security context to query
        security_query = f"{query} (malware OR threat OR attack OR vulnerability OR exploit)"

        result = await self.search_engine.search(security_query, num_results=10)

        return {
            "query": query,
            "security_query": security_query,
            "results": result.get("results", []),
            "timestamp": datetime.now().isoformat()
        }

    async def search_remediation(self, issue: str) -> Dict:
        """Search for remediation guidance"""
        log(f"Searching remediation for: {issue[:50]}")

        queries = [
            f'{issue} remediation mitigation fix',
            f'{issue} incident response playbook',
            f'{issue} detection prevention'
        ]

        all_results = []
        for query in queries:
            result = await self.search_engine.search(query, num_results=5)
            all_results.extend(result.get("results", []))

        return {
            "issue": issue,
            "remediation_results": all_results[:10],
            "timestamp": datetime.now().isoformat()
        }

    async def validate_finding(self, finding: str, context: str = "") -> Dict:
        """Validate a security finding with web research"""
        log(f"Validating finding: {finding[:50]}")

        # Search for confirmation/validation
        validation_query = f'"{finding}" {context} security'
        result = await self.search_engine.search(validation_query, num_results=10)

        # Analyze results to determine confidence
        validation_score = 0
        supporting_sources = []

        for r in result.get("results", []):
            snippet = r.get("snippet", "").lower()
            finding_lower = finding.lower()

            # Check if snippet supports the finding
            if any(term in snippet for term in finding_lower.split()[:3]):
                validation_score += 10
                supporting_sources.append({
                    "title": r.get("title"),
                    "url": r.get("url"),
                    "relevance": "high" if finding_lower in snippet else "medium"
                })

        confidence = min(100, validation_score)

        return {
            "finding": finding,
            "context": context,
            "validation_confidence": confidence,
            "supporting_sources": supporting_sources[:5],
            "search_results": result.get("results", [])[:5],
            "timestamp": datetime.now().isoformat()
        }


class ComprehensiveResearcher:
    """
    Comprehensive research combining multiple sources for full context.
    """

    def __init__(self):
        self.web_search = WebSearchEngine()
        self.security_researcher = SecurityResearcher()

    async def full_research(self, topic: str, research_type: str = "general") -> Dict:
        """
        Perform comprehensive research on a topic.

        research_type can be:
        - "general": General web search
        - "threat": Threat intelligence focused
        - "ioc": IOC research
        - "mitre": MITRE ATT&CK research
        - "cve": CVE research
        - "remediation": Remediation guidance
        """
        log(f"Full research: {topic} (type={research_type})")

        results = {
            "topic": topic,
            "research_type": research_type,
            "timestamp": datetime.now().isoformat(),
            "sections": {}
        }

        # General search
        general_results = await self.web_search.search(topic, num_results=10)
        results["sections"]["general"] = general_results

        # Type-specific research
        if research_type == "threat" or research_type == "general":
            threat_results = await self.security_researcher.search_threat_intel(topic)
            results["sections"]["threat_intel"] = threat_results

        if research_type == "ioc":
            ioc_results = await self.security_researcher.research_ioc(topic)
            results["sections"]["ioc_research"] = ioc_results

        if research_type == "mitre" or "T1" in topic.upper():
            # Extract technique ID if present
            mitre_match = re.search(r'T\d{4}(?:\.\d{3})?', topic.upper())
            if mitre_match:
                mitre_results = await self.security_researcher.research_mitre_technique(mitre_match.group())
                results["sections"]["mitre_research"] = mitre_results

        if research_type == "cve" or "CVE-" in topic.upper():
            cve_match = re.search(r'CVE-\d{4}-\d+', topic.upper())
            if cve_match:
                cve_results = await self.security_researcher.research_cve(cve_match.group())
                results["sections"]["cve_research"] = cve_results

        if research_type == "remediation":
            remediation_results = await self.security_researcher.search_remediation(topic)
            results["sections"]["remediation"] = remediation_results

        # Compile all unique sources
        all_sources = []
        seen_urls = set()
        for section in results["sections"].values():
            for r in section.get("results", []) + section.get("research_results", []):
                if r.get("url") and r["url"] not in seen_urls:
                    seen_urls.add(r["url"])
                    all_sources.append(r)

        results["all_sources"] = all_sources[:20]
        results["total_sources"] = len(all_sources)

        return results

    async def research_for_triage(self, event_data: Dict) -> Dict:
        """
        Research relevant to triaging a security event.
        Searches for context on event type, IOCs, techniques, etc.
        """
        log("Researching for triage")

        research_tasks = []

        # Research event type
        event_type = event_data.get("event_type", "")
        if event_type:
            research_tasks.append(
                self.security_researcher.search_threat_intel(f"{event_type} attack technique")
            )

        # Research command line patterns
        command_line = event_data.get("command_line", "")
        if command_line:
            # Extract suspicious patterns
            if "-enc" in command_line.lower() or "encoded" in command_line.lower():
                research_tasks.append(
                    self.security_researcher.search_threat_intel("powershell encoded command malware")
                )
            if "invoke-" in command_line.lower():
                research_tasks.append(
                    self.security_researcher.search_threat_intel("powershell invoke expression malware")
                )

        # Research IOCs
        for field in ["src_ip", "dest_ip"]:
            ip = event_data.get(field)
            if ip and not ip.startswith(("10.", "192.168.", "172.")):  # Skip private IPs
                research_tasks.append(
                    self.security_researcher.research_ioc(ip, "ip")
                )

        for field in ["domain", "query"]:
            domain = event_data.get(field)
            if domain:
                research_tasks.append(
                    self.security_researcher.research_ioc(domain, "domain")
                )

        for field in ["file_hash", "hash", "md5", "sha256"]:
            hash_val = event_data.get(field)
            if hash_val:
                research_tasks.append(
                    self.security_researcher.research_ioc(hash_val, "hash")
                )

        # Execute all research in parallel
        if research_tasks:
            research_results = await asyncio.gather(*research_tasks, return_exceptions=True)
        else:
            research_results = []

        # Compile results
        compiled = {
            "event_type": event_type,
            "research_performed": len(research_tasks),
            "timestamp": datetime.now().isoformat(),
            "findings": []
        }

        for result in research_results:
            if isinstance(result, Exception):
                compiled["findings"].append({"error": str(result)})
            else:
                compiled["findings"].append(result)

        return compiled


web_search = WebSearchEngine()
security_researcher = SecurityResearcher()
comprehensive_researcher = ComprehensiveResearcher()


async def search_web(query: str, num_results: int = 10) -> Dict:
    """General web search"""
    return await web_search.search(query, num_results)


async def research_ioc(indicator: str) -> Dict:
    """Research an IOC"""
    return await security_researcher.research_ioc(indicator)


async def research_mitre(technique_id: str) -> Dict:
    """Research MITRE technique"""
    return await security_researcher.research_mitre_technique(technique_id)


async def research_cve(cve_id: str) -> Dict:
    """Research CVE"""
    return await security_researcher.research_cve(cve_id)


async def search_remediation(issue: str) -> Dict:
    """Search for remediation guidance"""
    return await security_researcher.search_remediation(issue)


async def validate_finding(finding: str, context: str = "") -> Dict:
    """Validate a security finding"""
    return await security_researcher.validate_finding(finding, context)


async def full_research(topic: str, research_type: str = "general") -> Dict:
    """Comprehensive research"""
    return await comprehensive_researcher.full_research(topic, research_type)


async def research_for_event_triage(event_data: Dict) -> Dict:
    """Research for event triage"""
    return await comprehensive_researcher.research_for_triage(event_data)
