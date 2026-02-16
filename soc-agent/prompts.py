"""
SOC Reasoning Prompts
Templates used by the LLM analyzer for triage, correlation, and reporting.
"""

# Alert Triage Prompt
TRIAGE_PROMPT = """
You are a senior SOC analyst performing alert triage.

## Alert Details
- Alert Name: {alert_name}
- Severity: {severity}
- Source: {source}
- Timestamp: {timestamp}

## Raw Event Data
{event_data}

## Analysis Instructions
1. Classify the alert (True Positive, False Positive, Benign True Positive)
2. Assess the severity (Critical, High, Medium, Low, Informational)
3. Identify MITRE ATT&CK techniques
4. Recommend response actions
5. Provide confidence score (0-100)

## Response Format
Provide structured analysis with clear reasoning.
"""

# Correlation Analysis Prompt
CORRELATION_PROMPT = """
You are analyzing potentially correlated security events.

## Events to Correlate
{events}

## Correlation Rules
- Failed login burst: Multiple failed logins from same source in short time
- PowerShell encoded command: Base64 encoded PowerShell execution
- Multiple process spawn: Unusual number of child processes

## Analysis Instructions
1. Identify patterns across events
2. Determine if events are related
3. Assess attack chain progression
4. Map to kill chain phase
5. Calculate correlation confidence

## Response Format
Provide correlation analysis with timeline and impact assessment.
"""

# Threat Hunt Prompt
THREAT_HUNT_PROMPT = """
You are conducting a proactive threat hunt.

## Hunt Hypothesis
{hypothesis}

## Available Data
{data_summary}

## Hunt Instructions
1. Identify indicators of compromise
2. Look for anomalous patterns
3. Check for persistence mechanisms
4. Verify lateral movement signs
5. Document findings

## Response Format
Provide hunt findings with evidence and recommendations.
"""

# Alert Summary Prompt
SUMMARY_PROMPT = """
Generate a concise executive summary of the following security events.

## Events
{events}

## Summary Requirements
- Total event count
- Critical findings
- Affected systems
- Recommended priorities
- Risk assessment

Keep summary under 200 words.
"""
