"""
Splunk Data Loader
Uploads sample security events to Splunk and creates alerts
"""
import os
import json
import time
import urllib3
from datetime import datetime
import httpx
from dotenv import load_dotenv

# Disable SSL warnings for local dev
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv(dotenv_path='../.env')

# Configuration from environment
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_HEC_PORT = int(os.getenv("SPLUNK_HEC_PORT", "8088"))

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

def log(msg, data=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")
    if data:
        print(f"  -> {data}")


def get_session_key():
    """Get Splunk session key for API auth"""
    log("Getting Splunk session key...")
    with httpx.Client(verify=False) as client:
        response = client.post(
            f"{BASE_URL}/services/auth/login",
            data={"username": SPLUNK_USERNAME, "password": SPLUNK_PASSWORD, "output_mode": "json"}
        )
        if response.status_code == 200:
            session_key = response.json()["sessionKey"]
            log("Session key obtained successfully")
            return session_key
        else:
            log(f"Failed to get session key: {response.status_code}", response.text)
            return None


def create_index(session_key, index_name="security_events"):
    """Create a new index for security events"""
    log(f"Creating index: {index_name}")
    headers = {"Authorization": f"Splunk {session_key}"}

    with httpx.Client(verify=False) as client:
        # Check if index exists
        check_response = client.get(
            f"{BASE_URL}/services/data/indexes/{index_name}",
            headers=headers,
            params={"output_mode": "json"}
        )

        if check_response.status_code == 200:
            log(f"Index {index_name} already exists")
            return True

        # Create index
        response = client.post(
            f"{BASE_URL}/services/data/indexes",
            headers=headers,
            data={"name": index_name, "output_mode": "json"}
        )

        if response.status_code in [200, 201, 409]:
            log(f"Index {index_name} created/exists")
            return True
        else:
            log(f"Failed to create index: {response.status_code}", response.text)
            return False


def upload_events(session_key, events, index_name="security_events"):
    """Upload events to Splunk via REST API"""
    log(f"Uploading {len(events)} events to index {index_name}")
    headers = {"Authorization": f"Splunk {session_key}"}

    uploaded = 0
    with httpx.Client(verify=False, timeout=30.0) as client:
        for event in events:
            # Format event for Splunk receivers/simple endpoint
            event_data = json.dumps(event)

            response = client.post(
                f"{BASE_URL}/services/receivers/simple",
                headers=headers,
                params={
                    "index": index_name,
                    "sourcetype": f"security:{event.get('event_type', 'generic')}",
                    "source": "ai_soc_sample_data",
                    "output_mode": "json"
                },
                content=event_data
            )

            if response.status_code == 200:
                uploaded += 1
            else:
                log(f"Failed to upload event: {response.status_code}")

    log(f"Uploaded {uploaded}/{len(events)} events successfully")
    return uploaded


def create_alert(session_key, alert_config):
    """Create a saved search/alert in Splunk"""
    log(f"Creating alert: {alert_config['name']}")
    headers = {"Authorization": f"Splunk {session_key}"}

    with httpx.Client(verify=False) as client:
        # Use nobody/search namespace for better permissions
        # Create new saved search
        response = client.post(
            f"{BASE_URL}/servicesNS/nobody/search/saved/searches",
            headers=headers,
            data={
                "name": alert_config["name"],
                "search": alert_config["search"],
                "description": alert_config.get("description", ""),
                "is_scheduled": "1",
                "cron_schedule": alert_config.get("cron", "*/5 * * * *"),
                "dispatch.earliest_time": alert_config.get("earliest", "-15m"),
                "dispatch.latest_time": alert_config.get("latest", "now"),
                "alert.severity": alert_config.get("severity", "3"),
                "alert_type": "always",
                "alert.track": "1",
                "actions": "notable",
                "output_mode": "json"
            }
        )

        if response.status_code in [200, 201]:
            log(f"Alert '{alert_config['name']}' created successfully")
            return True
        elif response.status_code == 409:
            log(f"Alert '{alert_config['name']}' already exists")
            return True
        else:
            log(f"Failed to create alert: {response.status_code}", response.text[:500])
            return False


def main():
    print("=" * 60)
    print("[*] Splunk Data Loader - Sample Security Events")
    print("=" * 60)

    # Get session key
    session_key = get_session_key()
    if not session_key:
        print("[!] Failed to authenticate to Splunk")
        return

    # Create index
    create_index(session_key, "security_events")

    # Load sample events
    log("Loading sample events from file...")
    with open("../sample_data/security_events.json", "r") as f:
        events = json.load(f)
    log(f"Loaded {len(events)} events")

    # Upload events
    upload_events(session_key, events, "security_events")

    # Wait for indexing
    log("Waiting for events to be indexed...")
    time.sleep(3)

    # Define alerts - covering all 9 attack scenarios in sample data
    alerts = [
        # === SCENARIO 1: APT/Brute Force ===
        {
            "name": "SOC_Brute_Force_Attack",
            "search": 'index=security_events event_type=authentication action=failure | stats count by src_ip, dest_ip, user | where count >= 5',
            "description": "Detects multiple failed authentication attempts indicating brute force attack (T1110.001)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Encoded_PowerShell",
            "search": 'index=security_events event_type=process_creation process=*powershell* (command_line=*-enc* OR command_line=*-encodedcommand* OR command_line=*frombase64* OR command_line=*-nop* OR command_line=*hidden*)',
            "description": "Detects PowerShell execution with encoded/hidden commands - potential malware (T1059.001)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Suspicious_Outbound_Connection",
            "search": 'index=security_events event_type=network_connection dest_port IN (443, 8443, 4444, 8080) bytes_out > 1000000 | stats sum(bytes_out) as total_bytes by src_ip, dest_ip, process',
            "description": "Detects large outbound data transfers - potential exfiltration (T1048)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Lateral_Movement",
            "search": 'index=security_events event_type=lateral_movement | stats count values(dest_host) as targets by host, user, method',
            "description": "Detects lateral movement activity using WMI, PSExec, or WinRM (T1021)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Persistence_Registry",
            "search": 'index=security_events event_type=registry_modification (registry_key=*Run* OR registry_key=*Services*)',
            "description": "Detects registry modifications for persistence (T1547.001)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Data_Exfiltration",
            "search": 'index=security_events (event_type=data_exfiltration OR (event_type=network_connection bytes_out > 100000000))',
            "description": "Detects potential data exfiltration activities (T1048)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Malicious_DNS",
            "search": 'index=security_events event_type=dns_query (query=*evil* OR query=*attacker* OR query=*c2* OR query=*exfil* OR query=*tunnel*)',
            "description": "Detects DNS queries to known malicious domains (T1071.004)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },

        # === SCENARIO 2: Phishing/Macro ===
        {
            "name": "SOC_Office_Spawns_Script",
            "search": 'index=security_events event_type=process_creation (parent_process=*EXCEL* OR parent_process=*WORD* OR parent_process=*outlook*) (process=*powershell* OR process=*cmd* OR process=*wscript* OR process=*cscript* OR process=*mshta*)',
            "description": "Detects Office applications spawning script interpreters - macro malware (T1204.002)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Process_Injection",
            "search": 'index=security_events event_type=process_injection | stats count by source_process, target_process, host, user',
            "description": "Detects process injection attempts (T1055)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },

        # === SCENARIO 3: Insider Threat ===
        {
            "name": "SOC_After_Hours_Access",
            "search": 'index=security_events event_type=authentication action=success | eval hour=strftime(_time, "%H") | where hour < 6 OR hour > 22 | stats count by user, host, src_ip',
            "description": "Detects successful logins outside business hours - insider threat indicator (T1078)",
            "severity": "3",  # Medium
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_USB_Data_Copy",
            "search": 'index=security_events (event_type=usb_device OR event_type=file_copy) | stats values(action) as actions values(destination) as destinations by user, host, device_name',
            "description": "Detects USB device connections and file copy operations (T1052.001)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Sensitive_File_Access",
            "search": 'index=security_events event_type=file_access (file_path=*HR* OR file_path=*Finance* OR file_path=*Legal* OR file_path=*Confidential* OR file_path=*SSN* OR file_path=*Salary*) | stats count values(file_path) as files by user, host',
            "description": "Detects access to sensitive file shares (T1530)",
            "severity": "3",  # Medium
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },

        # === SCENARIO 4: Ransomware ===
        {
            "name": "SOC_Shadow_Copy_Deletion",
            "search": 'index=security_events (event_type=shadow_copy_deletion OR (event_type=process_creation (command_line=*vssadmin*delete* OR command_line=*wmic*shadowcopy*delete*)))',
            "description": "Detects shadow copy deletion - ransomware indicator (T1490)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Ransomware_Indicators",
            "search": 'index=security_events ((event_type=process_creation command_line=*bcdedit*recoveryenabled*) OR event_type=file_modification files_encrypted>0 OR (event_type=file_creation file_path=*README*RESTORE* OR file_path=*DECRYPT*))',
            "description": "Detects ransomware behavior patterns (T1486)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Critical_Service_Stop",
            "search": 'index=security_events event_type=service_stop (service_name=VSS OR service_name=*SQL* OR service_name=*backup*) | stats count values(service_name) as services by host, user',
            "description": "Detects stopping of critical services - ransomware preparation (T1489)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },

        # === SCENARIO 5: Cryptominer ===
        {
            "name": "SOC_Web_Shell_Activity",
            "search": 'index=security_events event_type=web_attack (attack_type=*shell* OR attack_type=*traversal* OR uri=*cmd=* OR uri=*exec=*)',
            "description": "Detects web shell upload and access attempts (T1190, T1505.003)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Cryptominer_Activity",
            "search": 'index=security_events ((event_type=process_creation (command_line=*xmrig* OR command_line=*minerd* OR command_line=*stratum+tcp* OR command_line=*pool.*)) OR (event_type=network_connection connection_type=mining_pool) OR (event_type=system_performance cpu_usage>95))',
            "description": "Detects cryptomining activity (T1496)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Cron_Persistence",
            "search": 'index=security_events event_type=cron_job action=created | stats count by user, host, cron_entry',
            "description": "Detects new cron job creation for persistence (T1053.003)",
            "severity": "3",  # Medium
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },

        # === SCENARIO 7: Credential Dumping ===
        {
            "name": "SOC_LSASS_Access",
            "search": 'index=security_events event_type=lsass_access | stats count by source_process, host, user, access_type',
            "description": "Detects LSASS process access - credential dumping (T1003.001)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Credential_Dump_Tools",
            "search": 'index=security_events event_type=process_creation (process=*mimikatz* OR process=*procdump* OR command_line=*sekurlsa* OR command_line=*lsass.dmp*)',
            "description": "Detects credential dumping tools (T1003)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },

        # === SCENARIO 8: DNS Tunneling ===
        {
            "name": "SOC_DNS_Tunneling",
            "search": 'index=security_events event_type=dns_anomaly | stats count by domain, client_ip, query_count',
            "description": "Detects DNS tunneling via high-volume queries to single domain (T1071.004)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_DNS_TXT_Exfil",
            "search": 'index=security_events event_type=dns_query query_type=TXT | stats count by host, client_ip | where count > 10',
            "description": "Detects high volume DNS TXT queries - potential exfiltration (T1048.003)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },

        # === SCENARIO 9: Kerberoasting ===
        {
            "name": "SOC_Kerberoasting",
            "search": 'index=security_events event_type=kerberos_tgs_request encryption_type=RC4_HMAC | stats count values(service) as services by user, client_ip | where count > 3',
            "description": "Detects Kerberoasting - multiple TGS requests with weak encryption (T1558.003)",
            "severity": "5",  # Critical
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        },
        {
            "name": "SOC_Kerberos_Anomaly",
            "search": 'index=security_events event_type=kerberos_anomaly | stats count by user, alert, service_count',
            "description": "Detects Kerberos authentication anomalies (T1558)",
            "severity": "4",  # High
            "cron": "*/5 * * * *",
            "earliest": "-15m",
            "latest": "now"
        }
    ]

    # Create alerts
    log("Creating SOC alerts...")
    for alert in alerts:
        create_alert(session_key, alert)

    print("=" * 60)
    print("[+] Data loader complete!")
    print(f"[+] Uploaded {len(events)} security events")
    print(f"[+] Created {len(alerts)} SOC alerts")
    print("=" * 60)
    print("\n[*] Attack Scenarios Loaded:")
    print("    1. APT Intrusion (brute force -> C2 -> lateral movement -> exfil)")
    print("    2. Phishing/Macro (email -> Excel macro -> mshta -> PowerShell)")
    print("    3. Insider Threat (after-hours access -> USB exfil)")
    print("    4. Ransomware (RDP brute force -> shadow copy delete -> encrypt)")
    print("    5. Cryptominer (web exploit -> xmrig deployment)")
    print("    6. Normal Activity (false positive testing)")
    print("    7. Credential Dumping (LSASS access -> mimikatz)")
    print("    8. DNS Tunneling (TXT query exfiltration)")
    print("    9. Kerberoasting (TGS requests with RC4)")
    print("=" * 60)
    print("\n[*] Verify in Splunk:")
    print("    Search: index=security_events | stats count by event_type")
    print("    Alerts: Settings > Searches, Reports, and Alerts")
    print("=" * 60)


if __name__ == "__main__":
    main()
