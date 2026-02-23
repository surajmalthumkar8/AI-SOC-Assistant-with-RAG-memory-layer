"""
Correlation Rules Engine
Implements SOC detection correlation logic
"""
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any
from config import config

def log(message: str, data: Any = None):
    """Debug logger"""
    if config.DEBUG:
        timestamp = datetime.now().isoformat()
        print(f"[{timestamp}] [CORRELATION] {message}")
        if data:
            print(f"  Data: {data}")


class CorrelationRule:
    """Base class for correlation rules"""
    def __init__(self, name: str, description: str, mitre_id: str):
        self.name = name
        self.description = description
        self.mitre_id = mitre_id

    def evaluate(self, events: List[Dict]) -> Dict:
        raise NotImplementedError


class FailedLoginBurstRule(CorrelationRule):
    """Detect multiple failed logins from same source"""
    def __init__(self):
        super().__init__(
            name="failed_login_burst",
            description="Multiple failed authentication attempts from same source",
            mitre_id="T1110"
        )
        self.threshold = 5
        self.time_window_minutes = 5

    def evaluate(self, events: List[Dict]) -> Dict:
        log(f"Evaluating {self.name} rule", {"event_count": len(events)})

        # Group by source IP
        source_attempts = {}
        for event in events:
            source = event.get('src_ip', event.get('source', 'unknown'))
            if source not in source_attempts:
                source_attempts[source] = []
            source_attempts[source].append(event)

        # Check for burst pattern
        alerts = []
        for source, attempts in source_attempts.items():
            if len(attempts) >= self.threshold:
                alerts.append({
                    "source": source,
                    "attempt_count": len(attempts),
                    "severity": "high" if len(attempts) > 10 else "medium",
                    "confidence": min(95, 50 + len(attempts) * 5)
                })

        triggered = len(alerts) > 0
        log(f"Rule evaluation complete", {"triggered": triggered, "alerts": len(alerts)})

        return {
            "rule": self.name,
            "mitre_id": self.mitre_id,
            "triggered": triggered,
            "alerts": alerts,
            "description": self.description
        }


class PowerShellEncodedRule(CorrelationRule):
    """Detect encoded PowerShell command execution"""
    def __init__(self):
        super().__init__(
            name="powershell_encoded",
            description="PowerShell execution with Base64 encoded commands",
            mitre_id="T1059.001"
        )
        self.patterns = [
            r'-enc\s+[A-Za-z0-9+/=]+',
            r'-encodedcommand\s+[A-Za-z0-9+/=]+',
            r'frombase64string',
            r'\[convert\]::frombase64'
        ]

    def evaluate(self, events: List[Dict]) -> Dict:
        log(f"Evaluating {self.name} rule", {"event_count": len(events)})

        alerts = []
        for event in events:
            command_line = str(event.get('CommandLine', event.get('command', '')))

            for pattern in self.patterns:
                if re.search(pattern, command_line, re.IGNORECASE):
                    alerts.append({
                        "host": event.get('host', event.get('Computer', 'unknown')),
                        "command_preview": command_line[:100] + "..." if len(command_line) > 100 else command_line,
                        "pattern_matched": pattern,
                        "severity": "critical",
                        "confidence": 90
                    })
                    break

        triggered = len(alerts) > 0
        log(f"Rule evaluation complete", {"triggered": triggered, "alerts": len(alerts)})

        return {
            "rule": self.name,
            "mitre_id": self.mitre_id,
            "triggered": triggered,
            "alerts": alerts,
            "description": self.description
        }


class MultipleProcessSpawnRule(CorrelationRule):
    """Detect unusual process spawning patterns"""
    def __init__(self):
        super().__init__(
            name="multiple_process_spawn",
            description="Unusual number of child processes spawned",
            mitre_id="T1059"
        )
        self.threshold = 10
        self.suspicious_parents = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']

    def evaluate(self, events: List[Dict]) -> Dict:
        log(f"Evaluating {self.name} rule", {"event_count": len(events)})

        # Group by parent process
        parent_children = {}
        for event in events:
            parent = event.get('ParentImage', event.get('parent_process', 'unknown'))
            if parent not in parent_children:
                parent_children[parent] = []
            parent_children[parent].append(event)

        alerts = []
        for parent, children in parent_children.items():
            is_suspicious_parent = any(sp in parent.lower() for sp in self.suspicious_parents)
            if len(children) >= self.threshold or (is_suspicious_parent and len(children) >= 5):
                alerts.append({
                    "parent_process": parent,
                    "child_count": len(children),
                    "severity": "high" if is_suspicious_parent else "medium",
                    "confidence": 85 if is_suspicious_parent else 70
                })

        triggered = len(alerts) > 0
        log(f"Rule evaluation complete", {"triggered": triggered, "alerts": len(alerts)})

        return {
            "rule": self.name,
            "mitre_id": self.mitre_id,
            "triggered": triggered,
            "alerts": alerts,
            "description": self.description
        }


class CorrelationEngine:
    """Main correlation engine"""
    def __init__(self):
        self.rules = [
            FailedLoginBurstRule(),
            PowerShellEncodedRule(),
            MultipleProcessSpawnRule()
        ]
        log("Correlation engine initialized", {"rules": [r.name for r in self.rules]})

    def run_all_rules(self, events: List[Dict]) -> Dict:
        """Run all correlation rules against events"""
        log("Running all correlation rules", {"event_count": len(events)})

        results = {
            "timestamp": datetime.now().isoformat(),
            "total_events": len(events),
            "rules_evaluated": len(self.rules),
            "findings": []
        }

        for rule in self.rules:
            result = rule.evaluate(events)
            if result["triggered"]:
                results["findings"].append(result)

        results["alerts_generated"] = len(results["findings"])
        log("All rules evaluated", {"findings": results["alerts_generated"]})

        return results

    def run_specific_rule(self, rule_name: str, events: List[Dict]) -> Dict:
        """Run a specific rule by name"""
        for rule in self.rules:
            if rule.name == rule_name:
                return rule.evaluate(events)
        return {"error": f"Rule not found: {rule_name}"}


correlation_engine = CorrelationEngine()
