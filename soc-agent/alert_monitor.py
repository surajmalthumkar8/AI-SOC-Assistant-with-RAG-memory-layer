"""
Alert Monitor
Polls Splunk for new triggered alerts and runs automated triage on each.
"""
import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import httpx

from mcp_client import splunk_mcp, search_splunk, get_alerts
from enriched_analyzer import enriched_analyzer, analyze_with_enrichment, quick_triage
from web_enrichment import threat_intel


def log(msg: str, data: Any = None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [ALERT-MONITOR] {msg}")
    if data:
        print(f"  -> {json.dumps(data, indent=2, default=str)[:500]}")


class AlertMonitor:
    """
    Monitors Splunk for new security alerts and automatically:
    1. Fetches new alerts
    2. Enriches IOCs from web sources
    3. Analyzes with LLM
    4. Updates Splunk with investigation results
    """

    def __init__(self, poll_interval: int = 60):
        self.poll_interval = poll_interval  # seconds
        self.processed_alerts = set()  # Track processed alert IDs
        self.running = False
        self.stats = {
            "alerts_processed": 0,
            "true_positives": 0,
            "false_positives": 0,
            "enrichments_performed": 0,
            "llm_analyses": 0,
            "start_time": None
        }
        log(f"Alert Monitor initialized (poll_interval={poll_interval}s)")

    async def start(self):
        """Start the alert monitoring loop"""
        self.running = True
        self.stats["start_time"] = datetime.now().isoformat()
        log("Alert Monitor started")

        while self.running:
            try:
                await self._check_for_alerts()
                await asyncio.sleep(self.poll_interval)
            except Exception as e:
                log(f"Error in monitoring loop: {e}")
                await asyncio.sleep(10)  # Wait before retry

    async def stop(self):
        """Stop the alert monitoring loop"""
        self.running = False
        log("Alert Monitor stopped", self.stats)

    async def _check_for_alerts(self):
        """Check for new alerts and process them"""
        log("Checking for new alerts...")

        try:
            # Query for recent security events that haven't been triaged
            query = """
            search index=security_events earliest=-15m latest=now
            | where isnotnull(event_type)
            | eval event_id=_time."_".host."_".event_type
            | table _time, event_id, event_type, host, user, src_ip, dest_ip, command_line, file_hash, query, severity
            | head 20
            """

            result = await search_splunk(query)
            events = result.get("results", [])

            new_events = []
            for event in events:
                event_id = event.get("event_id", str(hash(json.dumps(event, default=str))))
                if event_id not in self.processed_alerts:
                    new_events.append(event)
                    self.processed_alerts.add(event_id)

            if new_events:
                log(f"Found {len(new_events)} new events to process")
                for event in new_events:
                    await self._process_alert(event)
            else:
                log("No new events found")

        except Exception as e:
            log(f"Failed to check for alerts: {e}")

    async def _process_alert(self, event: Dict):
        """Process a single alert through the enrichment and analysis pipeline"""
        event_type = event.get("event_type", "unknown")
        host = event.get("host", "unknown")
        log(f"Processing alert: {event_type} on {host}")

        try:
            # Step 1: Quick triage to determine priority
            triage_result = await quick_triage(event)
            self.stats["alerts_processed"] += 1

            priority = triage_result.get("triage", {}).get("priority", "P3")
            decision = triage_result.get("triage", {}).get("triage_decision", "investigate")

            log(f"Quick triage: {decision} ({priority})", triage_result.get("triage"))

            # Step 2: For P1/P2 or escalate decisions, do full analysis
            if priority in ["P1", "P2"] or decision == "escalate":
                log("High priority - performing full enriched analysis")
                full_analysis = await analyze_with_enrichment(event)
                self.stats["llm_analyses"] += 1
                self.stats["enrichments_performed"] += 1

                classification = full_analysis.get("analysis", {}).get("classification", "unknown")
                if "true_positive" in classification.lower():
                    self.stats["true_positives"] += 1
                elif "false_positive" in classification.lower():
                    self.stats["false_positives"] += 1

                # Step 3: Save investigation report to Splunk
                await self._save_investigation_report(event, full_analysis, triage_result)

            else:
                # For lower priority, just save triage result
                await self._save_triage_result(event, triage_result)

        except Exception as e:
            log(f"Failed to process alert: {e}")

    async def _save_investigation_report(self, event: Dict, analysis: Dict, triage: Dict):
        """Save full investigation report to Splunk"""
        log("Saving investigation report to Splunk")

        report = {
            "report_type": "investigation",
            "timestamp": datetime.now().isoformat(),
            "original_event": event,
            "triage": triage.get("triage", {}),
            "analysis": analysis.get("analysis", {}),
            "enrichment": analysis.get("enrichment", {}),
            "investigated_by": "AI_SOC_Agent",
            "llm_provider": analysis.get("llm_provider", "unknown")
        }

        try:
            await splunk_mcp.ingest_enrichment(
                event.get("event_id", "unknown"),
                report
            )
            log("Investigation report saved")
        except Exception as e:
            log(f"Failed to save investigation report: {e}")

    async def _save_triage_result(self, event: Dict, triage: Dict):
        """Save quick triage result to Splunk"""
        log("Saving triage result to Splunk")

        report = {
            "report_type": "triage",
            "timestamp": datetime.now().isoformat(),
            "event_id": event.get("event_id", "unknown"),
            "event_type": event.get("event_type", "unknown"),
            "host": event.get("host", "unknown"),
            "triage_decision": triage.get("triage", {}).get("triage_decision"),
            "priority": triage.get("triage", {}).get("priority"),
            "enrichment_summary": triage.get("enrichment_summary"),
            "triaged_by": "AI_SOC_Agent"
        }

        try:
            await splunk_mcp.ingest_enrichment(
                event.get("event_id", "unknown"),
                report
            )
            log("Triage result saved")
        except Exception as e:
            log(f"Failed to save triage result: {e}")

    def get_stats(self) -> Dict:
        """Get monitoring statistics"""
        return {
            **self.stats,
            "running": self.running,
            "alerts_in_memory": len(self.processed_alerts)
        }


class BatchProcessor:
    """
    Batch process alerts for investigation
    """

    def __init__(self):
        log("Batch Processor initialized")

    async def process_all_pending(self) -> Dict:
        """Process all pending security events"""
        log("Starting batch processing of pending events")

        # Get all unprocessed events from last 24 hours
        query = """
        search index=security_events earliest=-24h latest=now
        | where isnotnull(event_type)
        | table _time, event_type, host, user, src_ip, dest_ip, command_line, file_hash, query, severity
        | head 100
        """

        result = await search_splunk(query)
        events = result.get("results", [])

        log(f"Found {len(events)} events to process")

        reports = []
        for i, event in enumerate(events):
            log(f"Processing event {i+1}/{len(events)}")
            try:
                # Full analysis for each event
                analysis = await analyze_with_enrichment(event)
                reports.append({
                    "event": event,
                    "analysis": analysis
                })

                # Save to Splunk
                await splunk_mcp.ingest_enrichment(
                    f"batch_{i}_{datetime.now().timestamp()}",
                    {
                        "report_type": "batch_investigation",
                        "timestamp": datetime.now().isoformat(),
                        "event": event,
                        "analysis": analysis.get("analysis", {})
                    }
                )

            except Exception as e:
                log(f"Failed to process event: {e}")
                reports.append({
                    "event": event,
                    "error": str(e)
                })

        return {
            "status": "completed",
            "events_processed": len(events),
            "reports": reports,
            "timestamp": datetime.now().isoformat()
        }

    async def process_specific_events(self, event_filter: Dict) -> Dict:
        """Process events matching specific criteria"""
        log(f"Processing events with filter: {event_filter}")

        # Build query from filter
        conditions = []
        if event_filter.get("event_type"):
            conditions.append(f'event_type="{event_filter["event_type"]}"')
        if event_filter.get("host"):
            conditions.append(f'host="{event_filter["host"]}"')
        if event_filter.get("user"):
            conditions.append(f'user="{event_filter["user"]}"')
        if event_filter.get("src_ip"):
            conditions.append(f'src_ip="{event_filter["src_ip"]}"')

        where_clause = " AND ".join(conditions) if conditions else "isnotnull(event_type)"

        query = f"""
        search index=security_events earliest=-24h latest=now
        | where {where_clause}
        | table _time, event_type, host, user, src_ip, dest_ip, command_line, file_hash, query, severity
        | head 50
        """

        result = await search_splunk(query)
        events = result.get("results", [])

        log(f"Found {len(events)} matching events")

        reports = []
        for event in events:
            try:
                analysis = await analyze_with_enrichment(event)
                reports.append({
                    "event": event,
                    "analysis": analysis
                })
            except Exception as e:
                reports.append({
                    "event": event,
                    "error": str(e)
                })

        return {
            "status": "completed",
            "filter": event_filter,
            "events_processed": len(events),
            "reports": reports
        }


class IOCEnricher:
    """
    Standalone IOC enrichment tool
    """

    async def enrich_indicators(self, indicators: List[str]) -> List[Dict]:
        """Enrich a list of indicators"""
        log(f"Enriching {len(indicators)} indicators")

        results = []
        for indicator in indicators:
            try:
                enrichment = await threat_intel.enrich_indicator(indicator)
                results.append(enrichment)
            except Exception as e:
                results.append({
                    "indicator": indicator,
                    "error": str(e)
                })

        return results

    async def bulk_ip_lookup(self, ips: List[str]) -> Dict:
        """Bulk IP address lookup"""
        log(f"Bulk IP lookup for {len(ips)} IPs")

        results = {}
        for ip in ips:
            try:
                results[ip] = await threat_intel.enrich_indicator(ip, "ip")
            except Exception as e:
                results[ip] = {"error": str(e)}

        return {
            "ips_checked": len(ips),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }


alert_monitor = AlertMonitor()
batch_processor = BatchProcessor()
ioc_enricher = IOCEnricher()


async def start_monitoring(poll_interval: int = 60):
    """Start alert monitoring"""
    alert_monitor.poll_interval = poll_interval
    await alert_monitor.start()


async def stop_monitoring():
    """Stop alert monitoring"""
    await alert_monitor.stop()


def get_monitoring_stats() -> Dict:
    """Get monitoring statistics"""
    return alert_monitor.get_stats()


async def process_all_events() -> Dict:
    """Batch process all pending events"""
    return await batch_processor.process_all_pending()


async def enrich_iocs(indicators: List[str]) -> List[Dict]:
    """Enrich a list of IOCs"""
    return await ioc_enricher.enrich_indicators(indicators)
