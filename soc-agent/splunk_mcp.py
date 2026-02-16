"""
Splunk Native MCP Server Client
Connects directly to Splunk's REST API at /services/mcp.
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx
import re

# Configuration
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
SPLUNK_MCP_ENDPOINT = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/mcp"


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [SPLUNK-MCP] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:500]}")


class SplunkMCPServer:
    """
    Direct client for Splunk's native MCP server.

    Splunk MCP Server provides:
    - Natural language to SPL conversion
    - Direct search execution
    - Alert management
    - Knowledge object access
    - Data model queries
    """

    def __init__(self):
        self.base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
        self.mcp_url = SPLUNK_MCP_ENDPOINT

        # Authentication
        if SPLUNK_TOKEN:
            self.auth_header = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
            self.auth_type = "token"
        else:
            self.auth_header = None
            self.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)
            self.auth_type = "basic"

        log(f"Splunk MCP Server client initialized", {
            "endpoint": self.mcp_url,
            "auth_type": self.auth_type
        })

    async def _request(self, method: str, endpoint: str, data: Dict = None, params: Dict = None) -> Dict:
        """Make authenticated request to Splunk MCP server"""
        async with httpx.AsyncClient(verify=False, timeout=120.0) as client:
            url = f"{self.base_url}{endpoint}"

            kwargs = {
                "params": {**(params or {}), "output_mode": "json"}
            }

            if self.auth_header:
                kwargs["headers"] = self.auth_header
            else:
                kwargs["auth"] = self.auth

            if method == "GET":
                response = await client.get(url, **kwargs)
            else:
                kwargs["data"] = data or {}
                response = await client.post(url, **kwargs)

            if response.status_code in [200, 201]:
                try:
                    return response.json()
                except:
                    return {"raw": response.text}
            else:
                raise Exception(f"Splunk MCP error: {response.status_code} - {response.text[:300]}")

    async def test_connection(self) -> Dict:
        """Test connection to Splunk MCP server"""
        log("Testing Splunk MCP server connection...")
        try:
            # Test basic server info
            info = await self._request("GET", "/services/server/info")
            server_info = info.get("entry", [{}])[0].get("content", {})

            # Test MCP endpoint
            try:
                mcp_info = await self._request("GET", "/services/mcp")
                mcp_available = True
            except:
                mcp_available = False

            return {
                "status": "connected",
                "server_name": server_info.get("serverName"),
                "version": server_info.get("version"),
                "mcp_endpoint": self.mcp_url,
                "mcp_available": mcp_available,
                "auth_type": self.auth_type
            }
        except Exception as e:
            log(f"Connection test failed: {e}")
            return {"status": "error", "error": str(e)}

    async def get_mcp_capabilities(self) -> Dict:
        """Get MCP server capabilities and available tools"""
        log("Getting MCP capabilities...")
        try:
            result = await self._request("GET", "/services/mcp")
            return {
                "capabilities": result,
                "endpoint": self.mcp_url
            }
        except Exception as e:
            # Return standard Splunk MCP capabilities
            return {
                "tools": [
                    {"name": "search", "description": "Execute SPL search query"},
                    {"name": "natural_language_search", "description": "Convert natural language to SPL and execute"},
                    {"name": "get_alerts", "description": "Get triggered alerts"},
                    {"name": "get_saved_searches", "description": "List saved searches"},
                    {"name": "get_indexes", "description": "List available indexes"},
                    {"name": "get_data_models", "description": "List data models"},
                    {"name": "create_alert", "description": "Create a new alert"}
                ],
                "error": str(e) if str(e) else None
            }

    async def execute_search(self, query: str, earliest: str = "-24h", latest: str = "now", max_results: int = 100) -> Dict:
        """Execute SPL search query"""
        log(f"Executing search: {query[:80]}...")

        # Create search job
        job_result = await self._request("POST", "/services/search/jobs", {
            "search": f"search {query}" if not query.strip().startswith("search") and not query.strip().startswith("|") else query,
            "earliest_time": earliest,
            "latest_time": latest,
            "exec_mode": "blocking",
            "max_count": max_results
        })

        sid = job_result.get("sid")
        if not sid:
            # Try to extract from response
            for entry in job_result.get("entry", []):
                if entry.get("content", {}).get("sid"):
                    sid = entry["content"]["sid"]
                    break

        if not sid:
            raise Exception(f"Failed to get search ID: {job_result}")

        # Get results
        results = await self._request("GET", f"/services/search/jobs/{sid}/results", params={"count": max_results})

        return {
            "sid": sid,
            "query": query,
            "result_count": len(results.get("results", [])),
            "results": results.get("results", [])
        }

    async def natural_language_to_spl(self, question: str) -> Dict:
        """
        Use Splunk MCP's natural language capability to convert question to SPL.
        Falls back to basic pattern matching if MCP NL is not available.
        """
        log(f"Converting to SPL: {question[:50]}...")

        # Try MCP natural language endpoint if available
        try:
            result = await self._request("POST", "/services/mcp/nl2spl", {
                "query": question
            })
            return {
                "original_question": question,
                "spl": result.get("spl"),
                "method": "mcp_native"
            }
        except:
            # Fallback: Basic pattern matching for common security queries
            spl = self._basic_nl_to_spl(question)
            return {
                "original_question": question,
                "spl": spl,
                "method": "pattern_matching"
            }

    def _basic_nl_to_spl(self, question: str) -> str:
        """Basic natural language to SPL conversion"""
        question_lower = question.lower()

        # Failed logins / brute force
        if any(term in question_lower for term in ["failed login", "brute force", "authentication failure"]):
            return 'index=security_events (event_type="brute_force" OR event_type="authentication_failure") | stats count by src_ip, user, host | sort -count'

        # PowerShell activity
        if "powershell" in question_lower:
            return 'index=security_events event_type="process_creation" process="*powershell*" | table _time, host, user, command_line'

        # Lateral movement
        if "lateral movement" in question_lower:
            return 'index=security_events event_type="lateral_movement" | table _time, host, user, src_ip, dest_ip, process'

        # Data exfiltration
        if any(term in question_lower for term in ["exfiltration", "data theft", "large transfer"]):
            return 'index=security_events event_type="data_exfiltration" | table _time, host, user, dest_ip, bytes_out'

        # Suspicious DNS
        if "dns" in question_lower:
            return 'index=security_events event_type="dns_query" | stats count by query | sort -count | head 50'

        # Specific IP
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', question)
        if ip_match:
            ip = ip_match.group()
            return f'index=security_events (src_ip="{ip}" OR dest_ip="{ip}") | table _time, event_type, host, user, src_ip, dest_ip'

        # Specific user
        if "user" in question_lower:
            user_match = re.search(r'user\s+(\w+)', question_lower)
            if user_match:
                user = user_match.group(1)
                return f'index=security_events user="{user}" | table _time, event_type, host, src_ip, command_line'

        # Specific host
        if "host" in question_lower or "workstation" in question_lower or "server" in question_lower:
            host_match = re.search(r'(host|workstation|server)\s+(\w+)', question_lower)
            if host_match:
                host = host_match.group(2)
                return f'index=security_events host="*{host}*" | table _time, event_type, user, src_ip, command_line'

        # Default: recent security events
        return 'index=security_events | head 100 | table _time, event_type, host, user, src_ip, severity'

    async def get_alerts(self, count: int = 50) -> List[Dict]:
        """Get recently triggered alerts"""
        log(f"Getting triggered alerts (count={count})...")

        result = await self._request("GET", "/services/alerts/fired_alerts")

        alerts = []
        for entry in result.get("entry", [])[:count]:
            content = entry.get("content", {})
            alerts.append({
                "name": entry.get("name"),
                "trigger_time": content.get("trigger_time"),
                "severity": content.get("severity"),
                "sid": content.get("sid"),
                "triggered_count": content.get("triggered_alert_count", 1)
            })

        return alerts

    async def get_saved_searches(self) -> List[Dict]:
        """Get saved searches (alerts definitions)"""
        log("Getting saved searches...")

        result = await self._request("GET", "/services/saved/searches")

        searches = []
        for entry in result.get("entry", []):
            content = entry.get("content", {})
            if content.get("is_scheduled") or content.get("alert_type"):
                searches.append({
                    "name": entry.get("name"),
                    "search": content.get("search"),
                    "is_scheduled": content.get("is_scheduled"),
                    "cron_schedule": content.get("cron_schedule"),
                    "alert_type": content.get("alert_type")
                })

        return searches

    async def get_indexes(self) -> List[Dict]:
        """Get available indexes"""
        log("Getting indexes...")

        result = await self._request("GET", "/services/data/indexes")

        indexes = []
        for entry in result.get("entry", []):
            content = entry.get("content", {})
            indexes.append({
                "name": entry.get("name"),
                "total_event_count": content.get("totalEventCount"),
                "current_db_size_mb": content.get("currentDBSizeMB")
            })

        return indexes

    async def ingest_event(self, index: str, sourcetype: str, event_data: Dict) -> Dict:
        """Ingest event to Splunk"""
        log(f"Ingesting event to {index}/{sourcetype}")

        result = await self._request("POST", "/services/receivers/simple", {
            "index": index,
            "sourcetype": sourcetype,
            "source": "ai_soc_agent",
            "event": json.dumps(event_data)
        })

        return {"status": "ingested", "index": index, "sourcetype": sourcetype}

    async def ask_splunk(self, question: str) -> Dict:
        """
        High-level natural language interface to Splunk.
        Converts question to SPL, executes, and returns results.
        """
        log(f"Ask Splunk: {question[:50]}...")

        # Convert to SPL
        spl_result = await self.natural_language_to_spl(question)
        spl_query = spl_result.get("spl")

        if not spl_query:
            return {"error": "Could not convert question to SPL"}

        # Execute search
        search_result = await self.execute_search(spl_query)

        return {
            "question": question,
            "spl_generated": spl_query,
            "method": spl_result.get("method"),
            "result_count": search_result.get("result_count", 0),
            "results": search_result.get("results", [])
        }


class MCPToolRunner:
    """
    Runs MCP tools using the mcp-remote protocol.
    Exposes MCP tools for external consumers.
    """

    def __init__(self):
        self.mcp_server = SplunkMCPServer()

    def get_mcp_config(self) -> Dict:
        """Get MCP configuration for external clients"""
        token = SPLUNK_TOKEN if SPLUNK_TOKEN else "YOUR_TOKEN_HERE"

        return {
            "mcpServers": {
                "splunk-mcp-server": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "mcp-remote",
                        SPLUNK_MCP_ENDPOINT,
                        "--header",
                        f"Authorization: Bearer {token}"
                    ]
                }
            }
        }

    async def run_tool(self, tool_name: str, parameters: Dict) -> Dict:
        """Run an MCP tool"""
        log(f"Running MCP tool: {tool_name}", parameters)

        tools = {
            "search": self._tool_search,
            "ask": self._tool_ask,
            "get_alerts": self._tool_get_alerts,
            "get_indexes": self._tool_get_indexes,
            "ingest": self._tool_ingest,
            "capabilities": self._tool_capabilities
        }

        if tool_name not in tools:
            return {"error": f"Unknown tool: {tool_name}"}

        return await tools[tool_name](parameters)

    async def _tool_search(self, params: Dict) -> Dict:
        return await self.mcp_server.execute_search(
            params.get("query", ""),
            params.get("earliest", "-24h"),
            params.get("latest", "now")
        )

    async def _tool_ask(self, params: Dict) -> Dict:
        return await self.mcp_server.ask_splunk(params.get("question", ""))

    async def _tool_get_alerts(self, params: Dict) -> Dict:
        alerts = await self.mcp_server.get_alerts(params.get("count", 50))
        return {"alerts": alerts, "count": len(alerts)}

    async def _tool_get_indexes(self, params: Dict) -> Dict:
        indexes = await self.mcp_server.get_indexes()
        return {"indexes": indexes}

    async def _tool_ingest(self, params: Dict) -> Dict:
        return await self.mcp_server.ingest_event(
            params.get("index", "security_events"),
            params.get("sourcetype", "ai:enrichment"),
            params.get("event", {})
        )

    async def _tool_capabilities(self, params: Dict) -> Dict:
        return await self.mcp_server.get_mcp_capabilities()


# Singleton instances
splunk_mcp_server = SplunkMCPServer()
mcp_tool_runner = MCPToolRunner()


# Convenience functions
async def test_splunk_mcp() -> Dict:
    """Test Splunk MCP connection"""
    return await splunk_mcp_server.test_connection()


async def search_splunk_mcp(query: str, earliest: str = "-24h", latest: str = "now") -> Dict:
    """Execute Splunk search via MCP"""
    return await splunk_mcp_server.execute_search(query, earliest, latest)


async def ask_splunk_natural(question: str) -> Dict:
    """Ask Splunk a question in natural language"""
    return await splunk_mcp_server.ask_splunk(question)


async def get_splunk_alerts() -> List[Dict]:
    """Get triggered alerts"""
    return await splunk_mcp_server.get_alerts()


def get_mcp_client_config() -> Dict:
    """Get MCP client configuration for external consumers"""
    return mcp_tool_runner.get_mcp_config()
