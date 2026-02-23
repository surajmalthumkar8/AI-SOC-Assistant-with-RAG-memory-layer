# Lateral Movement Response Playbook

## Overview
This playbook covers detection and response to lateral movement activity within the network. Lateral movement is a post-compromise technique where adversaries move through a network to find and access target data, systems, or resources. Covers MITRE ATT&CK techniques T1021 (Remote Services), T1047 (WMI), T1053 (Scheduled Task), T1570 (Lateral Tool Transfer).

## Common Lateral Movement Methods

### Remote Desktop Protocol (T1021.001)
- RDP logons (Event ID 4624, Logon Type 10)
- Unusual RDP source-destination pairs
- RDP to servers from non-admin workstations

### Windows Remote Management / WinRM (T1021.006)
- PowerShell remoting (Enter-PSSession, Invoke-Command)
- WinRM connections on port 5985/5986
- PSExec-style remote execution

### Windows Management Instrumentation (T1047)
- wmic.exe /node:REMOTE_HOST process call create
- WMI event subscriptions for persistence
- Remote process creation via WMI

### SMB/Windows Admin Shares (T1021.002)
- Connections to C$, ADMIN$, IPC$ shares
- File copy to remote hosts via SMB
- PsExec or similar tools using admin shares

### SSH (T1021.004)
- SSH connections between internal hosts
- SSH from Windows hosts (unusual in many environments)
- Key-based auth from unexpected sources

## Severity Assessment

### Critical
- Lateral movement TO domain controllers or critical servers
- Movement using privileged/admin credentials
- Multiple hosts accessed in rapid succession (automated tool)
- Movement combined with data staging or exfiltration indicators

### High
- Movement to file servers or database servers
- WMI remote process creation
- PsExec or similar remote execution tool detected
- Movement FROM an already-compromised host

### Medium
- RDP to servers during non-business hours
- WinRM connections from non-admin workstations
- Single hop lateral movement without further indicators

### Low
- Admin-to-admin RDP during business hours (routine administration)
- Scheduled task-based management tool activity
- Authorized remote administration tools (SCCM, etc.)

## Investigation Steps

### Step 1: Map the Movement Path
```spl
index=security_events event_type="lateral_movement"
| table _time, user, host, dest_host, dest_ip, method, process, command_line
| sort _time
```

Build a timeline: Source host -> Destination host -> Method used -> Credentials used

### Step 2: Identify the Initial Compromise
Work backwards from the lateral movement to find patient zero:
```spl
index=security_events user="SUSPICIOUS_USER" earliest=-7d
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count by host, event_type
| sort first_seen
```

### Step 3: Check What Happened on Each Destination
For each host the attacker moved to:
```spl
index=security_events host="DESTINATION_HOST" user="SUSPICIOUS_USER"
| table _time, event_type, process, command_line, dest_ip
| sort _time
```

Look for: data access, credential dumping, persistence installation, additional lateral movement

### Step 4: Check for Data Staging and Exfiltration
```spl
index=security_events host="DESTINATION_HOST" (event_type="data_exfiltration" OR event_type="file_access" OR bytes_out>1000000)
| table _time, user, dest_ip, bytes_out, file_path
```

### Step 5: Assess Credential Exposure
- Were credentials dumped on any of the accessed hosts?
- What privilege level did the compromised account have?
- Could the attacker have escalated privileges?
- Are any service account credentials at risk?

### Step 6: Containment
- Isolate ALL compromised hosts (source and destinations)
- Disable the compromised user account(s)
- Block lateral movement protocols between segments if possible
- Reset credentials for all accounts used during the movement

### Step 7: Remediation
- Clean each compromised host or reimage if necessary
- Remove any persistence mechanisms installed
- Reset ALL credentials that may have been accessible from compromised hosts
- Review and restrict lateral movement protocols (RDP, WinRM, WMI)
- Implement network segmentation to limit future lateral movement
- Deploy or verify EDR on all endpoints

## Common False Positive Scenarios
- IT administrators performing routine maintenance via RDP/WinRM
- Configuration management tools pushing updates
- Backup software accessing remote hosts
- Monitoring agents collecting data from remote hosts
- Authorized penetration testing
- Software deployment systems (SCCM, PDQ Deploy, etc.)
