"""
Threat Intelligence Enrichment
Queries VirusTotal, AbuseIPDB, Shodan, GreyNoise, URLhaus, and AlienVault OTX.
"""
import os
import re
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx

# API Keys from environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [WEB-ENRICHMENT] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:300]}")


class IndicatorType:
    """Indicator type detection"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


def detect_indicator_type(indicator: str) -> str:
    """Auto-detect the type of indicator"""
    indicator = indicator.strip()

    # IP Address (IPv4)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
        return IndicatorType.IP

    # URL
    if indicator.startswith(('http://', 'https://', 'hxxp://', 'hxxps://')):
        return IndicatorType.URL

    # Email
    if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', indicator):
        return IndicatorType.EMAIL

    # MD5 hash (32 hex chars)
    if re.match(r'^[a-fA-F0-9]{32}$', indicator):
        return IndicatorType.HASH_MD5

    # SHA1 hash (40 hex chars)
    if re.match(r'^[a-fA-F0-9]{40}$', indicator):
        return IndicatorType.HASH_SHA1

    # SHA256 hash (64 hex chars)
    if re.match(r'^[a-fA-F0-9]{64}$', indicator):
        return IndicatorType.HASH_SHA256

    # Domain (contains dots, not IP)
    if '.' in indicator and not indicator.startswith(('http://', 'https://')):
        return IndicatorType.DOMAIN

    return IndicatorType.UNKNOWN


class VirusTotalEnricher:
    """VirusTotal API integration for file, URL, IP, and domain analysis"""

    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.enabled = bool(self.api_key)

    async def lookup_ip(self, ip: str) -> Dict:
        """Look up IP address reputation"""
        if not self.enabled:
            return {"source": "virustotal", "status": "api_key_not_configured"}

        log(f"VirusTotal IP lookup: {ip}")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    f"{self.base_url}/ip_addresses/{ip}",
                    headers={"x-apikey": self.api_key}
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "source": "virustotal",
                        "indicator": ip,
                        "type": "ip",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": data.get("reputation", 0),
                        "country": data.get("country", "unknown"),
                        "as_owner": data.get("as_owner", "unknown"),
                        "verdict": "malicious" if stats.get("malicious", 0) > 3 else "suspicious" if stats.get("malicious", 0) > 0 else "clean"
                    }
                else:
                    return {"source": "virustotal", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "virustotal", "error": str(e)}

    async def lookup_domain(self, domain: str) -> Dict:
        """Look up domain reputation"""
        if not self.enabled:
            return {"source": "virustotal", "status": "api_key_not_configured"}

        log(f"VirusTotal domain lookup: {domain}")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    f"{self.base_url}/domains/{domain}",
                    headers={"x-apikey": self.api_key}
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "source": "virustotal",
                        "indicator": domain,
                        "type": "domain",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "categories": data.get("categories", {}),
                        "registrar": data.get("registrar", "unknown"),
                        "creation_date": data.get("creation_date"),
                        "verdict": "malicious" if stats.get("malicious", 0) > 3 else "suspicious" if stats.get("malicious", 0) > 0 else "clean"
                    }
                else:
                    return {"source": "virustotal", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "virustotal", "error": str(e)}

    async def lookup_hash(self, file_hash: str) -> Dict:
        """Look up file hash"""
        if not self.enabled:
            return {"source": "virustotal", "status": "api_key_not_configured"}

        log(f"VirusTotal hash lookup: {file_hash[:16]}...")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers={"x-apikey": self.api_key}
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "source": "virustotal",
                        "indicator": file_hash,
                        "type": "file_hash",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "file_type": data.get("type_description", "unknown"),
                        "file_name": data.get("meaningful_name", "unknown"),
                        "file_size": data.get("size", 0),
                        "magic": data.get("magic", "unknown"),
                        "verdict": "malicious" if stats.get("malicious", 0) > 5 else "suspicious" if stats.get("malicious", 0) > 0 else "clean"
                    }
                elif response.status_code == 404:
                    return {"source": "virustotal", "indicator": file_hash, "verdict": "not_found"}
                else:
                    return {"source": "virustotal", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "virustotal", "error": str(e)}


class AbuseIPDBEnricher:
    """AbuseIPDB API for IP reputation"""

    def __init__(self):
        self.api_key = ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.enabled = bool(self.api_key)

    async def lookup_ip(self, ip: str) -> Dict:
        """Check IP reputation on AbuseIPDB"""
        if not self.enabled:
            return {"source": "abuseipdb", "status": "api_key_not_configured"}

        log(f"AbuseIPDB lookup: {ip}")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    f"{self.base_url}/check",
                    headers={
                        "Key": self.api_key,
                        "Accept": "application/json"
                    },
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": True
                    }
                )
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    return {
                        "source": "abuseipdb",
                        "indicator": ip,
                        "type": "ip",
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "is_public": data.get("isPublic", True),
                        "is_tor": data.get("isTor", False),
                        "country": data.get("countryCode", "unknown"),
                        "isp": data.get("isp", "unknown"),
                        "domain": data.get("domain", "unknown"),
                        "usage_type": data.get("usageType", "unknown"),
                        "verdict": "malicious" if data.get("abuseConfidenceScore", 0) > 50 else "suspicious" if data.get("abuseConfidenceScore", 0) > 20 else "clean"
                    }
                else:
                    return {"source": "abuseipdb", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "abuseipdb", "error": str(e)}


class ShodanEnricher:
    """Shodan API for IP/host information"""

    def __init__(self):
        self.api_key = SHODAN_API_KEY
        self.base_url = "https://api.shodan.io"
        self.enabled = bool(self.api_key)

    async def lookup_ip(self, ip: str) -> Dict:
        """Get host information from Shodan"""
        if not self.enabled:
            return {"source": "shodan", "status": "api_key_not_configured"}

        log(f"Shodan lookup: {ip}")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    f"{self.base_url}/shodan/host/{ip}",
                    params={"key": self.api_key}
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "source": "shodan",
                        "indicator": ip,
                        "type": "ip",
                        "ports": data.get("ports", []),
                        "hostnames": data.get("hostnames", []),
                        "country": data.get("country_name", "unknown"),
                        "city": data.get("city", "unknown"),
                        "org": data.get("org", "unknown"),
                        "isp": data.get("isp", "unknown"),
                        "asn": data.get("asn", "unknown"),
                        "os": data.get("os"),
                        "vulns": data.get("vulns", []),
                        "tags": data.get("tags", []),
                        "verdict": "suspicious" if data.get("vulns") or "malware" in data.get("tags", []) else "informational"
                    }
                elif response.status_code == 404:
                    return {"source": "shodan", "indicator": ip, "verdict": "not_found"}
                else:
                    return {"source": "shodan", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "shodan", "error": str(e)}


class GreyNoiseEnricher:
    """GreyNoise API for IP noise/benign classification"""

    def __init__(self):
        self.api_key = GREYNOISE_API_KEY
        self.base_url = "https://api.greynoise.io/v3"
        self.enabled = bool(self.api_key)

    async def lookup_ip(self, ip: str) -> Dict:
        """Check IP on GreyNoise (Community API)"""
        log(f"GreyNoise lookup: {ip}")

        # GreyNoise Community API (free, no key required)
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                headers = {"Accept": "application/json"}
                if self.api_key:
                    headers["key"] = self.api_key

                response = await client.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers=headers
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "source": "greynoise",
                        "indicator": ip,
                        "type": "ip",
                        "noise": data.get("noise", False),
                        "riot": data.get("riot", False),  # Known good/common IP
                        "classification": data.get("classification", "unknown"),
                        "name": data.get("name", "unknown"),
                        "link": data.get("link", ""),
                        "last_seen": data.get("last_seen", ""),
                        "message": data.get("message", ""),
                        "verdict": "benign" if data.get("riot") else "noise" if data.get("noise") else "unknown"
                    }
                elif response.status_code == 404:
                    return {"source": "greynoise", "indicator": ip, "verdict": "not_seen", "noise": False}
                else:
                    return {"source": "greynoise", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "greynoise", "error": str(e)}


class URLhausEnricher:
    """URLhaus API for malicious URL lookup (free, no API key)"""

    def __init__(self):
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    async def lookup_url(self, url: str) -> Dict:
        """Check URL on URLhaus"""
        log(f"URLhaus lookup: {url[:50]}...")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/url/",
                    data={"url": url}
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("query_status") == "ok":
                        return {
                            "source": "urlhaus",
                            "indicator": url,
                            "type": "url",
                            "threat": data.get("threat", "unknown"),
                            "url_status": data.get("url_status", "unknown"),
                            "host": data.get("host", "unknown"),
                            "date_added": data.get("date_added", ""),
                            "tags": data.get("tags", []),
                            "payloads": len(data.get("payloads", [])),
                            "verdict": "malicious"
                        }
                    else:
                        return {"source": "urlhaus", "indicator": url, "verdict": "not_found"}
                else:
                    return {"source": "urlhaus", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "urlhaus", "error": str(e)}

    async def lookup_host(self, host: str) -> Dict:
        """Check host/domain on URLhaus"""
        log(f"URLhaus host lookup: {host}")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/host/",
                    data={"host": host}
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("query_status") == "ok":
                        return {
                            "source": "urlhaus",
                            "indicator": host,
                            "type": "host",
                            "url_count": data.get("url_count", 0),
                            "urls": data.get("urls", [])[:5],  # First 5 URLs
                            "verdict": "malicious" if data.get("url_count", 0) > 0 else "clean"
                        }
                    else:
                        return {"source": "urlhaus", "indicator": host, "verdict": "not_found"}
                else:
                    return {"source": "urlhaus", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "urlhaus", "error": str(e)}


class AlienVaultOTXEnricher:
    """AlienVault OTX API for threat intelligence"""

    def __init__(self):
        self.api_key = ALIENVAULT_API_KEY
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.enabled = bool(self.api_key)

    async def lookup_ip(self, ip: str) -> Dict:
        """Get IP reputation from AlienVault OTX"""
        if not self.enabled:
            return {"source": "alienvault_otx", "status": "api_key_not_configured"}

        log(f"AlienVault OTX lookup: {ip}")
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    f"{self.base_url}/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": self.api_key}
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "source": "alienvault_otx",
                        "indicator": ip,
                        "type": "ip",
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "reputation": data.get("reputation", 0),
                        "country": data.get("country_name", "unknown"),
                        "asn": data.get("asn", "unknown"),
                        "verdict": "malicious" if data.get("pulse_info", {}).get("count", 0) > 5 else "suspicious" if data.get("pulse_info", {}).get("count", 0) > 0 else "clean"
                    }
                else:
                    return {"source": "alienvault_otx", "error": f"Status {response.status_code}"}
            except Exception as e:
                return {"source": "alienvault_otx", "error": str(e)}


class ThreatIntelAggregator:
    """
    Aggregates threat intelligence from multiple sources.
    Provides unified enrichment for IOCs.
    """

    def __init__(self):
        self.virustotal = VirusTotalEnricher()
        self.abuseipdb = AbuseIPDBEnricher()
        self.shodan = ShodanEnricher()
        self.greynoise = GreyNoiseEnricher()
        self.urlhaus = URLhausEnricher()
        self.alienvault = AlienVaultOTXEnricher()

        log("Threat Intel Aggregator initialized", {
            "virustotal": self.virustotal.enabled,
            "abuseipdb": self.abuseipdb.enabled,
            "shodan": self.shodan.enabled,
            "greynoise": "community_api",
            "urlhaus": "free_api",
            "alienvault_otx": self.alienvault.enabled
        })

    async def enrich_indicator(self, indicator: str, indicator_type: str = None) -> Dict:
        """Enrich a single indicator from all available sources"""
        if not indicator_type:
            indicator_type = detect_indicator_type(indicator)

        log(f"Enriching {indicator_type}: {indicator}")

        results = {
            "indicator": indicator,
            "type": indicator_type,
            "timestamp": datetime.now().isoformat(),
            "sources": []
        }

        # Gather enrichment based on indicator type
        tasks = []

        if indicator_type == IndicatorType.IP:
            tasks = [
                self.virustotal.lookup_ip(indicator),
                self.abuseipdb.lookup_ip(indicator),
                self.shodan.lookup_ip(indicator),
                self.greynoise.lookup_ip(indicator),
                self.alienvault.lookup_ip(indicator)
            ]
        elif indicator_type == IndicatorType.DOMAIN:
            tasks = [
                self.virustotal.lookup_domain(indicator),
                self.urlhaus.lookup_host(indicator)
            ]
        elif indicator_type == IndicatorType.URL:
            tasks = [
                self.urlhaus.lookup_url(indicator)
            ]
        elif indicator_type in [IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256]:
            tasks = [
                self.virustotal.lookup_hash(indicator)
            ]

        if tasks:
            # Run all lookups in parallel
            source_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in source_results:
                if isinstance(result, Exception):
                    results["sources"].append({"error": str(result)})
                else:
                    results["sources"].append(result)

        # Calculate overall verdict
        results["verdict"] = self._aggregate_verdict(results["sources"])
        results["risk_score"] = self._calculate_risk_score(results["sources"])

        return results

    async def enrich_event(self, event_data: Dict) -> Dict:
        """Extract and enrich all IOCs from an event"""
        log("Enriching event IOCs")

        iocs_to_enrich = []

        # Extract IP addresses
        for field in ["src_ip", "dest_ip", "client_ip", "server_ip"]:
            if event_data.get(field):
                iocs_to_enrich.append(event_data[field])

        # Extract domains
        for field in ["domain", "query", "host", "dest_host"]:
            if event_data.get(field) and "." in event_data[field]:
                iocs_to_enrich.append(event_data[field])

        # Extract file hashes
        for field in ["file_hash", "md5", "sha1", "sha256", "hash"]:
            if event_data.get(field):
                iocs_to_enrich.append(event_data[field])

        # Extract URLs
        for field in ["url", "request_url", "referrer"]:
            if event_data.get(field):
                iocs_to_enrich.append(event_data[field])

        # Deduplicate
        iocs_to_enrich = list(set(iocs_to_enrich))

        # Enrich all IOCs
        enrichment_results = []
        for ioc in iocs_to_enrich:
            result = await self.enrich_indicator(ioc)
            enrichment_results.append(result)

        return {
            "event_enrichment": True,
            "iocs_enriched": len(enrichment_results),
            "timestamp": datetime.now().isoformat(),
            "enrichments": enrichment_results,
            "overall_risk": self._calculate_event_risk(enrichment_results)
        }

    def _aggregate_verdict(self, sources: List[Dict]) -> str:
        """Aggregate verdicts from multiple sources"""
        verdicts = [s.get("verdict", "unknown") for s in sources if "verdict" in s]

        if "malicious" in verdicts:
            return "malicious"
        elif "suspicious" in verdicts:
            return "suspicious"
        elif verdicts and all(v in ["clean", "benign", "not_found", "not_seen"] for v in verdicts):
            return "clean"
        else:
            return "unknown"

    def _calculate_risk_score(self, sources: List[Dict]) -> int:
        """Calculate risk score 0-100 based on source results"""
        score = 0
        count = 0

        for source in sources:
            if source.get("verdict") == "malicious":
                score += 100
                count += 1
            elif source.get("verdict") == "suspicious":
                score += 50
                count += 1
            elif source.get("verdict") == "clean":
                score += 0
                count += 1

            # Add points for specific indicators
            if source.get("abuse_confidence_score"):
                score += source["abuse_confidence_score"]
                count += 1

            if source.get("malicious", 0) > 0:
                score += min(source["malicious"] * 10, 100)
                count += 1

        return min(100, score // max(count, 1))

    def _calculate_event_risk(self, enrichments: List[Dict]) -> str:
        """Calculate overall event risk from all enrichments"""
        risk_scores = [e.get("risk_score", 0) for e in enrichments]

        if not risk_scores:
            return "unknown"

        max_risk = max(risk_scores)
        if max_risk >= 70:
            return "critical"
        elif max_risk >= 50:
            return "high"
        elif max_risk >= 30:
            return "medium"
        elif max_risk >= 10:
            return "low"
        else:
            return "informational"


# Singleton instance
threat_intel = ThreatIntelAggregator()


# Convenience functions
async def enrich_ioc(indicator: str) -> Dict:
    """Enrich a single IOC"""
    return await threat_intel.enrich_indicator(indicator)


async def enrich_event_iocs(event_data: Dict) -> Dict:
    """Enrich all IOCs in an event"""
    return await threat_intel.enrich_event(event_data)


async def lookup_ip(ip: str) -> Dict:
    """Quick IP lookup"""
    return await threat_intel.enrich_indicator(ip, IndicatorType.IP)


async def lookup_domain(domain: str) -> Dict:
    """Quick domain lookup"""
    return await threat_intel.enrich_indicator(domain, IndicatorType.DOMAIN)


async def lookup_hash(file_hash: str) -> Dict:
    """Quick hash lookup"""
    return await threat_intel.enrich_indicator(file_hash)


async def lookup_url(url: str) -> Dict:
    """Quick URL lookup"""
    return await threat_intel.enrich_indicator(url, IndicatorType.URL)
