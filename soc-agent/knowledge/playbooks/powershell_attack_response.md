# PowerShell Attack Response Playbook

## Overview
This playbook covers the investigation and response to suspicious or malicious PowerShell execution detected in the environment. PowerShell is frequently abused by threat actors for execution, download of additional payloads, and lateral movement (MITRE T1059.001).

## Severity Indicators

### Critical (Immediate Action Required)
- Base64-encoded commands (-enc, -EncodedCommand)
- Download cradles (Invoke-WebRequest, Net.WebClient, DownloadString, DownloadFile)
- Execution policy bypass (-ExecutionPolicy Bypass)
- Hidden window execution (-WindowStyle Hidden, -w hidden)
- AMSI bypass attempts
- Reflective PE injection via PowerShell

### High
- Invoke-Expression (IEX) usage
- PowerShell remoting to other hosts (Enter-PSSession, Invoke-Command)
- Credential access cmdlets (Get-Credential, mimikatz)
- Registry modification via PowerShell

### Medium
- Unusual PowerShell execution by non-admin users
- PowerShell spawned from Office applications
- Scheduled task creation via PowerShell

### Low / Benign
- Administrative cmdlets (Get-Service, Get-Process, Get-EventLog)
- System maintenance scripts from known admin accounts
- Configuration management tool execution (SCCM, Puppet, Chef)

## Investigation Steps

### Step 1: Decode the Command
If the command uses -enc or -EncodedCommand, decode the Base64 payload:
```
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ENCODED_STRING'))
```
Document the decoded command for further analysis.

### Step 2: Identify the Kill Chain Phase
- Is this initial access (download cradle)?
- Is this execution of a staged payload?
- Is this lateral movement (remoting, WMI)?
- Is this persistence (scheduled tasks, registry)?
- Is this data collection or exfiltration?

### Step 3: Check the Parent Process
Legitimate PowerShell is typically launched from:
- explorer.exe (user-initiated)
- services.exe (scheduled tasks)
- svchost.exe (group policy)
- Configuration management agents

Suspicious parents include:
- winword.exe, excel.exe (Office macro execution)
- wscript.exe, cscript.exe (script host)
- mshta.exe (HTA execution)
- cmd.exe spawned from unusual processes

### Step 4: Query Splunk for Context
```spl
index=security_events host="AFFECTED_HOST" process="*powershell*"
| table _time, user, parent_process, command_line, pid, ppid
| sort -_time
```

Check for related activity from the same user:
```spl
index=security_events user="AFFECTED_USER" earliest=-24h
| stats count by event_type, host
| sort -count
```

### Step 5: Check for Network Connections
Look for outbound connections from the PowerShell process:
```spl
index=security_events host="AFFECTED_HOST" (dest_port=80 OR dest_port=443 OR dest_port=8080)
| table _time, src_ip, dest_ip, dest_port, process
```

### Step 6: Containment
- If confirmed malicious: Isolate the host from the network immediately
- Kill the PowerShell process and any child processes
- Block the C2 IP/domain at the firewall
- Reset credentials for the affected user account

### Step 7: Remediation
- Remove any dropped files or payloads
- Remove persistence mechanisms (scheduled tasks, registry keys)
- Scan the host with updated AV/EDR
- Check for lateral movement to other hosts
- Review and rotate any credentials that may have been exposed

## Common False Positive Scenarios
- System administrators running maintenance scripts
- Configuration management tools (SCCM, Puppet, Ansible)
- Software deployment scripts
- Monitoring agents that use PowerShell for data collection
- Developers running build or test scripts
