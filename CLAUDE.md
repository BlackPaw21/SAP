# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This repository contains **SOC Analyst training and assessment materials** - specifically a Tier-1 SOC Analyst Interactive Assessment with answer key. This is an educational/testing resource, not a software development project.

## Contents

- **SOC_ANALYST_TEST.md**: 90-minute assessment covering networking, web attacks, firewall rules, malware analysis, security devices, and log analysis
- **SOC_ANSWER_KEY.md**: Comprehensive answer key with detailed explanations, attack analysis, and MITRE ATT&CK framework mappings

## Assessment Structure

The test (100 points, 70% passing) covers six main sections:

1. **Networking Fundamentals (20 pts)**: OSI model, ports/protocols, packet analysis
2. **Web Attacks (25 pts)**: XSS, SQL injection, path traversal, CSRF, DDoS defenses
3. **Firewall Rules (15 pts)**: Rule analysis, security issues, rule creation
4. **Malware & Persistence (20 pts)**: Registry keys, scheduled tasks, services, indicators of compromise
5. **Security Gateways & Devices (20 pts)**: IDS/IPS, WAF, Email Gateway, NGFW, EDR, SIEM
6. **Log Analysis Practical (20 pts)**: Multi-source log correlation identifying 11+ hidden incidents

## Key Learning Areas

### Attack Techniques Covered
- Brute force authentication attacks
- Lateral movement via SMB
- Command & Control (C2) via IRC
- DNS tunneling and Domain Generation Algorithms (DGA)
- Privilege escalation and persistence mechanisms
- IDOR (Insecure Direct Object Reference) exploitation
- Phishing and Business Email Compromise (BEC)
- Data exfiltration

### Security Indicators
- IRC traffic (port 6667)
- Tor connections (port 9001, 185.220.101.0/24)
- PowerShell with encoded commands (`-enc`, `-ep bypass`)
- mimikatz execution on Domain Controllers
- Double file extensions (.pdf.exe)
- Sequential port scanning
- Workstation-to-workstation SMB (unusual)
- Impossible travel scenarios

### MITRE ATT&CK Techniques Referenced
- T1110: Brute Force
- T1021.002: SMB/Windows Admin Shares
- T1071.001: Application Layer Protocol (C2)
- T1568.002: Domain Generation Algorithms
- T1547.001: Registry Run Keys
- T1053.005: Scheduled Task
- T1543.003: Windows Service
- T1059.001: PowerShell

## Working with This Repository

### Analysis Tasks
When asked to analyze the assessment:
- Identify incident patterns across log sources (firewall, web server, Windows events, DNS, email gateway)
- Correlate timestamps and IP addresses across different log sets
- Apply MITRE ATT&CK framework to map attack techniques
- Prioritize incidents by severity (Critical > High > Medium > Low)

### Grading/Scoring
- Each section has specific point allocations (see SOC_ANSWER_KEY.md lines 660-695)
- Bonus question adds 5 points (attack timeline reconstruction)
- Passing score: 70/100

### Common Patterns to Recognize
1. **Brute force → Success → Privilege escalation** (critical severity)
2. **Sequential connections** (lateral movement, port scanning, IDOR)
3. **Unusual protocols** (IRC, Tor) in corporate environments
4. **Typosquatting domains** (company-inc.com vs company.com)
5. **Process parent-child anomalies** (excel.exe → powershell.exe)

## No Build/Test Commands

This is a document-only repository with no code to build, test, or run. All content is Markdown-based educational material.
