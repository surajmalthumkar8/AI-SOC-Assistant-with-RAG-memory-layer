"""
Splunk MCP Client
Handles communication with the MCP connector and Splunk REST API.
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx

# Load configuration
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_MCP_ENDPOINT = os.getenv("SPLUNK_MCP_ENDPOINT", f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/mcp")


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [MCP-CLIENT] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:500]}")


class SplunkMCPClient:
    """
    Client for Splunk's native MCP (Model Context Protocol) server.

    MCP allows AI models to interact with Splunk using natural language
    and structured tool calls.
    """

    def __init__(self):
        self.base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
        self.mcp_url = SPLUNK_MCP_ENDPOINT
        self.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)
        self.session_id = None
        log(f"MCP Client initialized for {self.mcp_url}")

    async def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make authenticated request to Splunk"""
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            url = f"{self.base_url}{endpoint}"

            if method == "GET":
                response = await client.get(
                    url,
                    auth=self.auth,
                    params={"output_mode": "json"}
                )
            else:
                response = await client.post(
                    url,
                    auth=self.auth,
                    data={**data, "output_mode": "json"} if data else {"output_mode": "json"}
                )

            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Splunk API error: {response.status_code} - {response.text[:200]}")

    async def test_connection(self) -> Dict:
        """Test connection to Splunk MCP server"""
        log("Testing Splunk MCP connection...")
        try:
            result = await self._make_request("GET", "/services/server/info")
            server_info = result.get("entry", [{}])[0].get("content", {})
            return {
                "status": "connected",
                "server_name": server_info.get("serverName"),
                "version": server_info.get("version"),
                "mcp_endpoint": self.mcp_url
            }
        except Exception as e:
            log(f"Connection test failed: {e}")
            return {"status": "error", "error": str(e)}

    async def list_mcp_tools(self) -> List[Dict]:
        """List available MCP tools from Splunk"""
        log("Listing MCP tools...")
        try:
            # Query the MCP endpoint for available tools
            result = await self._make_request("GET", "/services/mcp")
            return result.get("entry", [])
        except Exception as e:
            log(f"Failed to list MCP tools: {e}")
            # Return default Splunk capabilities as tools
            return [
                {"name": "search", "description": "Execute SPL search query"},
                {"name": "get_alerts", "description": "Get triggered alerts"},
                {"name": "get_notable", "description": "Get notable events"},
                {"name": "update_notable", "description": "Update notable event status"}
            ]

    async def execute_search(self, query: str, earliest: str = "-24h", latest: str = "now") -> Dict:
        """Execute SPL search query via MCP"""
        log(f"Executing search: {query[:100]}...")

        # Create search job
        create_result = await self._make_request("POST", "/services/search/jobs", {
            "search": query,
            "earliest_time": earliest,
            "latest_time": latest,
            "exec_mode": "blocking"  # Wait for completion
        })

        sid = create_result.get("sid")
        if not sid:
            raise Exception("Failed to get search ID")

        # Get results
        results = await self._make_request("GET", f"/services/search/jobs/{sid}/results")

        return {
            "sid": sid,
            "result_count": len(results.get("results", [])),
            "results": results.get("results", [])
        }

    async def get_triggered_alerts(self, count: int = 50) -> List[Dict]:
        """Get recently triggered alerts"""
        log(f"Fetching triggered alerts (count={count})...")

        result = await self._make_request("GET", f"/services/alerts/fired_alerts")

        alerts = []
        for entry in result.get("entry", [])[:count]:
            alerts.append({
                "name": entry.get("name"),
                "trigger_time": entry.get("content", {}).get("trigger_time"),
                "severity": entry.get("content", {}).get("severity"),
                "sid": entry.get("content", {}).get("sid")
            })

        return alerts

    async def get_notable_events(self, status: str = "new", count: int = 50) -> List[Dict]:
        """Get notable events (ES) or security alerts"""
        log(f"Fetching notable events (status={status})...")

        # Search for recent security events
        query = f"""
        search index=security_events
        | head {count}
        | table _time, event_type, host, user, src_ip, dest_ip, severity, command_line
        """

        result = await self.execute_search(query)
        return result.get("results", [])

    async def update_notable_status(self, event_id: str, status: str, comment: str) -> Dict:
        """Update notable event status with investigation notes"""
        log(f"Updating notable {event_id} to status: {status}")

        # Create investigation report as event
        report_data = {
            "event_id": event_id,
            "status": status,
            "comment": comment,
            "updated_at": datetime.now().isoformat(),
            "updated_by": "AI_SOC_Agent"
        }

        # Index the update
        result = await self._make_request("POST", "/services/receivers/simple", {
            "index": "security_events",
            "sourcetype": "investigation:update",
            "source": "ai_soc_agent",
            "event": json.dumps(report_data)
        })

        return {"status": "updated", "event_id": event_id, "new_status": status}

    async def ingest_enrichment(self, event_id: str, enrichment_data: Dict) -> Dict:
        """Ingest enrichment data back to Splunk"""
        log(f"Ingesting enrichment for event {event_id}")

        enrichment_event = {
            "event_id": event_id,
            "enrichment_type": "ai_analysis",
            "timestamp": datetime.now().isoformat(),
            **enrichment_data
        }

        result = await self._make_request("POST", "/services/receivers/simple", {
            "index": "security_events",
            "sourcetype": "enrichment:ai",
            "source": "ai_soc_agent",
            "event": json.dumps(enrichment_event)
        })

        return {"status": "ingested", "event_id": event_id}


class MCPToolExecutor:
    """
    Executes MCP tool calls from LLM responses.
    Maps tool names to actual Splunk operations.
    """

    def __init__(self, mcp_client: SplunkMCPClient):
        self.client = mcp_client
        self.tools = {
            "splunk_search": self._tool_search,
            "get_alerts": self._tool_get_alerts,
            "get_events": self._tool_get_events,
            "update_status": self._tool_update_status,
            "enrich_event": self._tool_enrich_event
        }

    async def execute_tool(self, tool_name: str, parameters: Dict) -> Dict:
        """Execute a tool by name with given parameters"""
        if tool_name not in self.tools:
            return {"error": f"Unknown tool: {tool_name}"}

        log(f"Executing tool: {tool_name}", parameters)
        return await self.tools[tool_name](parameters)

    async def _tool_search(self, params: Dict) -> Dict:
        """Execute Splunk search"""
        query = params.get("query", "")
        earliest = params.get("earliest", "-24h")
        latest = params.get("latest", "now")
        return await self.client.execute_search(query, earliest, latest)

    async def _tool_get_alerts(self, params: Dict) -> Dict:
        """Get triggered alerts"""
        count = params.get("count", 50)
        alerts = await self.client.get_triggered_alerts(count)
        return {"alerts": alerts, "count": len(alerts)}

    async def _tool_get_events(self, params: Dict) -> Dict:
        """Get notable events"""
        status = params.get("status", "new")
        count = params.get("count", 50)
        events = await self.client.get_notable_events(status, count)
        return {"events": events, "count": len(events)}

    async def _tool_update_status(self, params: Dict) -> Dict:
        """Update event status"""
        event_id = params.get("event_id")
        status = params.get("status")
        comment = params.get("comment", "")
        return await self.client.update_notable_status(event_id, status, comment)

    async def _tool_enrich_event(self, params: Dict) -> Dict:
        """Enrich event with data"""
        event_id = params.get("event_id")
        enrichment = params.get("enrichment", {})
        return await self.client.ingest_enrichment(event_id, enrichment)


# Singleton instances
splunk_mcp = SplunkMCPClient()
mcp_executor = MCPToolExecutor(splunk_mcp)


# Convenience functions
async def test_mcp_connection() -> Dict:
    """Test Splunk MCP connection"""
    return await splunk_mcp.test_connection()


async def search_splunk(query: str, earliest: str = "-24h", latest: str = "now") -> Dict:
    """Execute Splunk search"""
    return await splunk_mcp.execute_search(query, earliest, latest)


async def get_alerts() -> List[Dict]:
    """Get triggered alerts"""
    return await splunk_mcp.get_triggered_alerts()


async def get_security_events(count: int = 50) -> List[Dict]:
    """Get security events"""
    return await splunk_mcp.get_notable_events(count=count)


async def execute_mcp_tool(tool_name: str, params: Dict) -> Dict:
    """Execute MCP tool"""
    return await mcp_executor.execute_tool(tool_name, params)
