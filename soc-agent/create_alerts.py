"""
Create Splunk Alerts/Saved Searches
"""
import os
import urllib3
import httpx
from dotenv import load_dotenv

urllib3.disable_warnings()
load_dotenv(dotenv_path='../.env')

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

def get_session_key():
    with httpx.Client(verify=False) as client:
        response = client.post(
            f"{BASE_URL}/services/auth/login",
            data={"username": SPLUNK_USERNAME, "password": SPLUNK_PASSWORD, "output_mode": "json"}
        )
        if response.status_code == 200:
            return response.json()["sessionKey"]
    return None

def create_alert(session_key, name, search, description, severity="3"):
    """Create saved search/alert"""
    print(f"[*] Creating alert: {name}")
    headers = {"Authorization": f"Splunk {session_key}"}

    with httpx.Client(verify=False) as client:
        # Use the correct endpoint without namespace restrictions
        response = client.post(
            f"{BASE_URL}/services/saved/searches",
            headers=headers,
            data={
                "name": name,
                "search": search,
                "description": description,
                "is_scheduled": "1",
                "cron_schedule": "*/5 * * * *",
                "dispatch.earliest_time": "-1h",
                "dispatch.latest_time": "now",
                "alert.severity": severity,
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": "0",
                "alert.track": "1",
                "alert.suppress": "0",
                "actions": "",
                "output_mode": "json"
            }
        )

        if response.status_code in [200, 201]:
            print(f"    [+] Created successfully!")
            return True
        elif response.status_code == 409:
            print(f"    [!] Already exists")
            return True
        else:
            print(f"    [-] Failed: {response.status_code}")
            print(f"    Response: {response.text[:300]}")
            return False

def main():
    print("=" * 60)
    print("[*] Creating Splunk SOC Alerts")
    print("=" * 60)

    session_key = get_session_key()
    if not session_key:
        print("[-] Failed to get session key")
        return

    print("[+] Authenticated to Splunk")

    # Comprehensive alerts covering all 9 attack scenarios
    alerts = [
        # === SCENARIO 1: APT/Brute Force ===
        {"name": "AI_SOC_Brute_Force_Attack", "search": 'index=security_events event_type=authentication action=failure | stats count by src_ip, dest_ip, user | where count >= 5', "description": "Detects brute force attack (T1110.001)", "severity": "4"},
        {"name": "AI_SOC_Encoded_PowerShell", "search": 'index=security_events event_type=process_creation process=*powershell* (command_line=*-enc* OR command_line=*-nop* OR command_line=*hidden*)', "description": "Detects encoded/hidden PowerShell (T1059.001)", "severity": "5"},
        {"name": "AI_SOC_Large_Outbound_Transfer", "search": 'index=security_events event_type=network_connection bytes_out > 1000000 | stats sum(bytes_out) as total by src_ip, dest_ip', "description": "Detects large data transfers (T1048)", "severity": "4"},
        {"name": "AI_SOC_Lateral_Movement", "search": 'index=security_events event_type=lateral_movement | stats count values(dest_host) as targets by host, user, method', "description": "Detects lateral movement (T1021)", "severity": "5"},
        {"name": "AI_SOC_Persistence_Registry", "search": 'index=security_events event_type=registry_modification (registry_key=*Run* OR registry_key=*Services*)', "description": "Detects registry persistence (T1547.001)", "severity": "4"},
        {"name": "AI_SOC_Data_Exfiltration", "search": 'index=security_events (event_type=data_exfiltration OR (event_type=network_connection bytes_out > 100000000))', "description": "Detects data exfiltration (T1048)", "severity": "5"},
        {"name": "AI_SOC_Malicious_DNS", "search": 'index=security_events event_type=dns_query (query=*evil* OR query=*attacker* OR query=*c2* OR query=*tunnel*)', "description": "Detects malicious DNS (T1071.004)", "severity": "4"},

        # === SCENARIO 2: Phishing/Macro ===
        {"name": "AI_SOC_Office_Spawns_Script", "search": 'index=security_events event_type=process_creation (parent_process=*EXCEL* OR parent_process=*WORD*) (process=*powershell* OR process=*cmd* OR process=*mshta*)', "description": "Detects Office macro malware (T1204.002)", "severity": "5"},
        {"name": "AI_SOC_Process_Injection", "search": 'index=security_events event_type=process_injection | stats count by source_process, target_process, host', "description": "Detects process injection (T1055)", "severity": "5"},

        # === SCENARIO 3: Insider Threat ===
        {"name": "AI_SOC_After_Hours_Access", "search": 'index=security_events event_type=authentication action=success | eval hour=strftime(_time, "%H") | where hour < 6 OR hour > 22', "description": "Detects after-hours logins (T1078)", "severity": "3"},
        {"name": "AI_SOC_USB_Data_Copy", "search": 'index=security_events (event_type=usb_device OR event_type=file_copy) | stats count by user, host', "description": "Detects USB data theft (T1052.001)", "severity": "4"},
        {"name": "AI_SOC_Sensitive_File_Access", "search": 'index=security_events event_type=file_access (file_path=*HR* OR file_path=*Finance* OR file_path=*Legal*)', "description": "Detects sensitive file access (T1530)", "severity": "3"},

        # === SCENARIO 4: Ransomware ===
        {"name": "AI_SOC_Shadow_Copy_Deletion", "search": 'index=security_events (event_type=shadow_copy_deletion OR command_line=*vssadmin*delete* OR command_line=*shadowcopy*delete*)', "description": "Detects shadow copy deletion (T1490)", "severity": "5"},
        {"name": "AI_SOC_Ransomware_Indicators", "search": 'index=security_events (command_line=*bcdedit*recoveryenabled* OR files_encrypted>0 OR file_path=*README*RESTORE*)', "description": "Detects ransomware (T1486)", "severity": "5"},
        {"name": "AI_SOC_Critical_Service_Stop", "search": 'index=security_events event_type=service_stop (service_name=VSS OR service_name=*SQL*)', "description": "Detects service stops (T1489)", "severity": "5"},

        # === SCENARIO 5: Cryptominer ===
        {"name": "AI_SOC_Web_Shell_Activity", "search": 'index=security_events event_type=web_attack (attack_type=*shell* OR attack_type=*traversal*)', "description": "Detects web shells (T1505.003)", "severity": "5"},
        {"name": "AI_SOC_Cryptominer_Activity", "search": 'index=security_events (command_line=*xmrig* OR command_line=*minerd* OR connection_type=mining_pool OR cpu_usage>95)', "description": "Detects cryptominer (T1496)", "severity": "4"},
        {"name": "AI_SOC_Cron_Persistence", "search": 'index=security_events event_type=cron_job action=created', "description": "Detects cron persistence (T1053.003)", "severity": "3"},

        # === SCENARIO 7: Credential Dumping ===
        {"name": "AI_SOC_LSASS_Access", "search": 'index=security_events event_type=lsass_access | stats count by source_process, host', "description": "Detects LSASS access (T1003.001)", "severity": "5"},
        {"name": "AI_SOC_Credential_Dump_Tools", "search": 'index=security_events event_type=process_creation (process=*mimikatz* OR process=*procdump* OR command_line=*sekurlsa* OR command_line=*lsass.dmp*)', "description": "Detects credential tools (T1003)", "severity": "5"},

        # === SCENARIO 8: DNS Tunneling ===
        {"name": "AI_SOC_DNS_Tunneling", "search": 'index=security_events event_type=dns_anomaly | stats count by domain, client_ip', "description": "Detects DNS tunneling (T1071.004)", "severity": "5"},
        {"name": "AI_SOC_DNS_TXT_Exfil", "search": 'index=security_events event_type=dns_query query_type=TXT | stats count by host | where count > 10', "description": "Detects DNS TXT exfil (T1048.003)", "severity": "4"},

        # === SCENARIO 9: Kerberoasting ===
        {"name": "AI_SOC_Kerberoasting", "search": 'index=security_events event_type=kerberos_tgs_request encryption_type=RC4_HMAC | stats count by user | where count > 3', "description": "Detects Kerberoasting (T1558.003)", "severity": "5"},
        {"name": "AI_SOC_Kerberos_Anomaly", "search": 'index=security_events event_type=kerberos_anomaly | stats count by user, alert', "description": "Detects Kerberos anomalies (T1558)", "severity": "4"}
    ]

    created = 0
    for alert in alerts:
        if create_alert(session_key, alert["name"], alert["search"], alert["description"], alert["severity"]):
            created += 1

    print("=" * 60)
    print(f"[+] Created {created}/{len(alerts)} alerts")
    print("=" * 60)
    print("\n[*] Scenarios Covered:")
    print("    - APT Intrusion (brute force, C2, lateral movement)")
    print("    - Phishing/Macro (Office macro, process injection)")
    print("    - Insider Threat (after-hours, USB, sensitive files)")
    print("    - Ransomware (shadow copy deletion, encryption)")
    print("    - Cryptominer (web shell, mining activity)")
    print("    - Credential Dumping (LSASS, mimikatz)")
    print("    - DNS Tunneling (TXT exfiltration)")
    print("    - Kerberoasting (TGS requests)")
    print("=" * 60)
    print("\n[*] View alerts in Splunk:")
    print("    http://localhost:8000/en-GB/manager/search/saved/searches")
    print("    Or: Settings > Searches, Reports, and Alerts")
    print("=" * 60)

if __name__ == "__main__":
    main()
