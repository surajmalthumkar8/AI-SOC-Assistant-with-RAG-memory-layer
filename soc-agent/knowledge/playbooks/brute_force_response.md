# Brute Force Attack Response Playbook

## Overview
This playbook covers investigation and response to brute force and credential stuffing attacks detected via authentication logs. Maps to MITRE ATT&CK T1110 (Brute Force) and sub-techniques T1110.001 (Password Guessing), T1110.003 (Password Spraying), T1110.004 (Credential Stuffing).

## Detection Thresholds
- **Password Guessing**: 5+ failed logins to a single account from one source in 5 minutes
- **Password Spraying**: 3+ failed logins to different accounts from one source in 10 minutes
- **Credential Stuffing**: 10+ failed logins from one source across multiple accounts with different passwords
- **Distributed Brute Force**: 10+ failed logins to one account from different sources in 15 minutes

## Severity Assessment

### Critical
- Successful login AFTER multiple failures from same source (compromise likely)
- Attack targeting privileged accounts (Domain Admin, root, service accounts)
- Attack from known-malicious IP (check threat intel)
- Attack on externally-facing services (VPN, OWA, RDP)

### High
- Ongoing active brute force (> 50 attempts/hour)
- Attack from foreign IP against internal accounts
- Multiple accounts targeted simultaneously (spray attack)

### Medium
- Low-volume password guessing (< 20 attempts)
- Attack against non-privileged accounts
- Source IP is internal (possible compromised host or misconfigured service)

### Low
- Single failed login from known IP ranges
- Service account authentication failures (often misconfiguration)
- Failed logins matching known scanner patterns

## Investigation Steps

### Step 1: Quantify the Attack
```spl
index=security_events event_type="brute_force" OR event_type="authentication_failure"
| stats count as attempts, dc(user) as targeted_accounts, values(user) as users by src_ip
| sort -attempts
```

### Step 2: Check for Successful Logins
This is the most critical query - did the attacker succeed?
```spl
index=security_events src_ip="ATTACKER_IP" event_type="authentication_success"
| table _time, user, host, src_ip
```

### Step 3: Enrich the Source IP
- Check GreyNoise for scanner/bot classification
- Check AbuseIPDB for abuse reports
- Check internal asset inventory - is this an internal IP?
- Geo-locate the IP - is the country expected for your users?

### Step 4: Check Account Status
- Is the targeted account locked out?
- When was the password last changed?
- Does the account have MFA enabled?
- Is this a shared or service account?

### Step 5: Look for Post-Compromise Activity
If a successful login occurred after the brute force:
```spl
index=security_events user="COMPROMISED_USER" earliest=-1h
| table _time, event_type, host, src_ip, command_line, dest_ip
| sort _time
```

### Step 6: Containment
- **If compromise confirmed**: Disable the account immediately, force password reset
- **If attack ongoing**: Block source IP at firewall/WAF
- **If internal source**: Isolate the source host for investigation
- Enable account lockout if not already configured

### Step 7: Remediation
- Force password reset for any successfully accessed accounts
- Enable MFA for targeted accounts if not already enabled
- Review and tighten account lockout policies
- Add source IP to blocklist
- Check for password reuse across compromised and other accounts

## Common False Positive Scenarios
- User forgot password and is trying variations
- Service account with expired credentials in automated jobs
- Mobile devices with cached old credentials
- SSO or federation misconfigurations
- Vulnerability scanners during authorized testing
- Load balancers health-checking authentication endpoints
