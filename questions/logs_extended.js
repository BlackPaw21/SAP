/**
 * Extended Log Analysis Questions (log51-70)
 * Advanced SOC Analyst training - Complex log correlation
 * Lazy-loaded when user clicks "Load More Questions"
 */

const logsExtended = [
    {
        id: 'log51',
        title: 'AWS CloudTrail Privilege Escalation',
        points: 9,
        question: 'CloudTrail shows: CreateAccessKey (user:developer), AttachUserPolicy (policy:AdministratorAccess). What attack occurred?',
        type: 'radio',
        options: [
            { value: 'privesc', text: 'IAM privilege escalation attack' },
            { value: 'normal', text: 'Normal admin operations' },
            { value: 'audit', text: 'Security audit activity' },
            { value: 'backup', text: 'Backup account configuration' }
        ],
        correct: 'privesc',
        mitre: 'T1098',
        explanation: '☁️ AWS Privilege Escalation: Attacker with compromised "developer" user creates new access key → attaches AdministratorAccess policy → now has full AWS control. Attack chain: 1) Initial access (leaked creds, SSRF), 2) CreateAccessKey (new permanent creds), 3) AttachUserPolicy (escalate to admin). Detection: CloudTrail events (iam:AttachUserPolicy, iam:PutUserPolicy, iam:CreateAccessKey by non-admins), GuardDuty findings. Prevention: Least privilege IAM, SCPs blocking privilege escalation paths, MFA for sensitive actions. Hunt: Look for AssumeRole to admin roles, policy modifications, unusual API calls from compromised user. MITRE: T1098 (Account Manipulation).'
    },
    {
        id: 'log52',
        title: 'Kubernetes Pod Exec Audit Log',
        points: 8,
        question: 'K8s audit: verb=create, resource=pods/exec, user=system:node:worker-3, responseStatus=200. What happened?',
        type: 'radio',
        options: [
            { value: 'kubectl', text: 'kubectl exec into running pod - potential container breakout' },
            { value: 'deployment', text: 'Normal pod deployment' },
            { value: 'scaling', text: 'Auto-scaling event' },
            { value: 'monitoring', text: 'Health check probe' }
        ],
        correct: 'kubectl',
        mitre: 'T1609',
        explanation: '⚓ Container Exec: pods/exec = kubectl exec command. User=system:node (suspicious - nodes shouldn\'t exec, humans/automation should). Attack: Compromised node executes into pods → escape container → access secrets, lateral movement. Legitimate: DevOps troubleshooting (but should be service account, not node identity). Detection: Audit verb=create + resource=pods/exec, especially from node identities or unexpected users. Prevention: RBAC restricting exec permissions, admission controllers, runtime security (Falco). Investigate: What commands ran inside pod? Check container logs, process tree. MITRE: T1609 (Container Administration Command).'
    },
    {
        id: 'log53',
        title: 'Syslog Priority Field Anomaly',
        points: 7,
        question: 'Firewall syslog: <133>Jan 15 12:00:00 fw1 DENY vs <14>Jan 15 12:01:00 fw1 ALLOW. What do priority numbers indicate?',
        type: 'radio',
        options: [
            { value: 'severity', text: 'Facility (16) and Severity (5 vs 6' },
            { value: 'count', text: 'Event count/sequence number' },
            { value: 'version', text: 'Syslog protocol version' },
            { value: 'random', text: 'Random identifier' }
        ],
        correct: 'severity',
        mitre: 'T1562.001',
        explanation: '📊 Syslog Priority: <133> = (Facility × 8) + Severity. 133 = Facility 16 (local0) + Severity 5 (notice). <14> = Facility 1 (user) + Severity 6 (info). Severity: 0=emergency, 1=alert, 2=critical, 3=error, 4=warning, 5=notice, 6=info, 7=debug. DENY vs ALLOW having different facilities/severities is normal (different log sources or classifications). Detection use: Filter by severity for alert tuning, route critical (0-2) to 24/7 SOC. Attack: Malware may manipulate syslog severity to hide events (send as debug=7 instead of alert=1). SIEM parsing: Extract facility/severity for proper correlation. MITRE: T1562.001 (Disable/Modify Tools - log manipulation).'
    },
    {
        id: 'log54',
        title: 'Office 365 Inbox Rule Exfiltration',
        points: 8,
        question: 'O365 audit: Operation=New-InboxRule, Parameters=ForwardTo:external@evil.com, SubjectContains:"invoice". What attack?',
        type: 'radio',
        options: [
            { value: 'bec', text: 'BEC email exfiltration via inbox rule' },
            { value: 'auto_reply', text: 'Auto-reply configuration' },
            { value: 'vacation', text: 'Vacation forwarding' },
            { value: 'backup', text: 'Email backup setup' }
        ],
        correct: 'bec',
        mitre: 'T1114.003',
        explanation: '📧 BEC Persistence: Attacker creates hidden inbox rule forwarding emails to external address. Filters by subject ("invoice", "payment", "wire") to steal financial emails. Attack persists after password reset (rule survives). Detection: UnifiedAuditLog Operation=New-InboxRule/Set-InboxRule, especially with ForwardTo external domains. Hunt PowerShell: Get-InboxRule -Mailbox * | Where {$_.ForwardTo -ne $null}. Prevention: Alert on external forwarding, block auto-forwarding to untrusted domains, user training. Stealth: Rule often named innocuously (".", "spam filter"). Also check: New-TransportRule (org-wide), MailboxDelegate (access grants). MITRE: T1114.003 (Email Forwarding Rule).'
    },
    {
        id: 'log55',
        title: 'Linux Auditd Process Injection',
        points: 9,
        question: 'auditd: syscall=process_vm_writev, pid=1234, target_pid=5678, exe=/tmp/.hidden. What technique?',
        type: 'radio',
        options: [
            { value: 'inject', text: 'Process injection into running process' },
            { value: 'fork', text: 'Normal process fork/spawn' },
            { value: 'debug', text: 'Debugger attachment' },
            { value: 'ipc', text: 'Inter-process communication' }
        ],
        correct: 'inject',
        mitre: 'T1055',
        explanation: '💉 Process Injection: process_vm_writev = write to another process memory space (ptrace-based injection). Attacker writes malicious code into legitimate process (target_pid=5678) to evade detection, inherit permissions. Red flags: 1) exe=/tmp/.hidden (suspicious location/name), 2) Cross-process memory write, 3) No legitimate reason for injection. Techniques: ptrace injection, LD_PRELOAD, /proc/pid/mem writes. Detection: auditd rules monitoring process_vm_writev/process_vm_readv, ptrace syscalls. Prevention: SELinux/AppArmor restricting ptrace, Yama ptrace_scope=1 (only children). Investigate: What is target process 5678? What code injected? Memory forensics. MITRE: T1055 (Process Injection).'
    },
    {
        id: 'log56',
        title: 'Zeek (Bro) SSL Certificate Anomaly',
        points: 8,
        question: 'Zeek ssl.log: validation_status=self signed, server_name=update.windows.com. What does this indicate?',
        type: 'radio',
        options: [
            { value: 'mitm', text: 'SSL interception or MITM attack' },
            { value: 'normal', text: 'Normal Windows Update traffic' },
            { value: 'cdn', text: 'CDN caching behavior' },
            { value: 'ipv6', text: 'IPv6 configuration issue' }
        ],
        correct: 'mitm',
        mitre: 'T1557.001',
        explanation: '🔐 Certificate Mismatch: update.windows.com should have valid Microsoft CA-signed cert, NOT self-signed. Possibilities: 1) **Corporate SSL inspection** (proxy terminates TLS, re-signs with internal CA), 2) **MITM attack** (attacker intercepting Windows Update), 3) **Malware C2** (malware impersonating Windows Update domain). Investigation: Check if corporate proxy (expected), verify cert issuer (internal CA vs unknown), test from multiple vantage points. If malicious: DNS poisoning, ARP spoofing, rogue DHCP, BGP hijacking. Detection: Zeek monitors cert validation status, issuer changes, cert age. Legitimate corporate proxies: Should have proper internal CA distributed via GPO. MITRE: T1557.001 (LLMNR/NBT-NS Poisoning though broader MITM).'
    },
    {
        id: 'log57',
        title: 'Splunk SPL Injection Attack',
        points: 8,
        question: 'Splunk query from user dashboard: index=web user="admin" | eval command="\\" | delete index=security. What risk?',
        type: 'radio',
        options: [
            { value: 'injection', text: 'SPL injection leading to unauthorized data deletion' },
            { value: 'search', text: 'Normal search query' },
            { value: 'export', text: 'Data export operation' },
            { value: 'readonly', text: 'Read-only query with no risk' }
        ],
        correct: 'injection',
        mitre: 'T1565.001',
        explanation: '🔍 SPL Injection: Similar to SQL injection but for Splunk Search Processing Language. User input in dashboard (user="admin") breaks out with \\" → injects | delete command. Attack: Modify searches, delete data, escalate privileges (| makeresults | sendalert). Prevention: 1) **Input validation** (whitelist allowed chars), 2) **Parameterized tokens** ($user$ with proper escaping), 3) **RBAC** (restrict delete/sendalert capabilities), 4) **Audit searches** (monitor for dangerous commands). Dangerous SPL commands: delete, sendalert, outputlookup (overwrite), collect. Real risk: If dashboard uses user input without sanitization. Detection: Audit introspection logs for unusual search patterns. MITRE: T1565.001 (Stored Data Manipulation).'
    },
    {
        id: 'log58',
        title: 'VPN Concurrent Session Anomaly',
        points: 7,
        question: 'VPN logs: user=jsmith login from 203.0.113.5 (USA) and 45.142.120.10 (Russia) within 2 minutes. What does this suggest?',
        type: 'radio',
        options: [
            { value: 'compromise', text: 'Credential compromise - impossible travel' },
            { value: 'roaming', text: 'Mobile device roaming between networks' },
            { value: 'backup', text: 'Backup VPN connection' },
            { value: 'load', text: 'Load balancing across gateways' }
        ],
        correct: 'compromise',
        mitre: 'T1078',
        explanation: '🌍 Impossible Travel: User cannot physically be in USA and Russia 2 minutes apart (8000+ km). Indicates: 1) **Credential theft** - attacker using stolen credentials from different location, 2) **Account sharing** (policy violation), 3) **VPN chaining** (attacker routes through USA VPN). Detection: GeoIP analysis, calculate travel velocity (distance/time > airplane speed = impossible), alert on concurrent sessions from distant locations. UEBA tools detect this pattern. False positives: Cloud desktop (redirects through datacenters), satellite internet (unusual GeoIP). Action: Terminate both sessions, force password reset, MFA verification, investigate how creds leaked. Similar: O365 impossible travel alerts. MITRE: T1078 (Valid Accounts - compromised).'
    },
    {
        id: 'log59',
        title: 'EDR Parent-Child Process Anomaly',
        points: 9,
        question: 'EDR alert: Parent=winword.exe, Child=powershell.exe -enc <base64>, CommandLine includes IEX. What attack?',
        type: 'radio',
        options: [
            { value: 'macro', text: 'Malicious Office macro spawning PowerShell' },
            { value: 'update', text: 'Office update process' },
            { value: 'plugin', text: 'Office add-in installation' },
            { value: 'normal', text: 'Normal document scripting' }
        ],
        correct: 'macro',
        mitre: 'T1204.002',
        explanation: '📎 Malicious Macro: Word spawning PowerShell = macro execution (VBA script). Flags: 1) **-enc (encoded command)** hides malicious code, 2) **IEX (Invoke-Expression)** executes downloaded payload, 3) **Parent-child relationship** (winword→powershell abnormal). Attack flow: Phishing email → user enables macros → VBA runs → spawns PowerShell → downloads stage 2 (Emotet, Qakbot). Detection: Process monitoring (parent-child trees), command-line analysis (encoded PowerShell), EDR behavioral rules. Prevention: Disable macros via GPO, ASR rules (Office creating child processes), email filtering (.doc/.docm attachments). Investigate: What did PowerShell download? Network connections? Other affected users? MITRE: T1204.002 (Malicious File).'
    },
    {
        id: 'log60',
        title: 'Docker Container Escape Detection',
        points: 9,
        question: 'Container runtime log: container_id=a1b2c3, syscall=mount, flags=--privileged, target=/host/root. What occurred?',
        type: 'radio',
        options: [
            { value: 'escape', text: 'Container escape via privileged mode mount' },
            { value: 'normal', text: 'Normal container volume mount' },
            { value: 'backup', text: 'Container backup operation' },
            { value: 'update', text: 'Container update process' }
        ],
        correct: 'escape',
        mitre: 'T1611',
        explanation: '🐋 Container Breakout: Privileged container can mount host filesystem (/host/root) → full host access. Attack: 1) Exploit app in container, 2) Discover --privileged flag, 3) mount /dev/sda1 /mnt → read/write host disk, 4) Schedule cron jobs on host, modify /etc/shadow. Detection: RuntimeAudit logs, Falco rules (privileged container + mount syscall), monitor Docker API for --privileged. Prevention: **Never use --privileged in prod**, use security contexts (readOnlyRootFilesystem), seccomp/AppArmor profiles, admission controllers (PSP/Pod Security Standards). Other escapes: hostPath volumes, hostNetwork, hostPID. MITRE: T1611 (Escape to Host).'
    },
    {
        id: 'log61',
        title: 'NGINX Access Log SQL Injection',
        points: 7,
        question: 'NGINX: GET /search?q=1\' UNION SELECT password FROM users-- HTTP/1.1 200. What happened?',
        type: 'radio',
        options: [
            { value: 'sqli_success', text: 'Successful SQL injection - HTTP 200 indicates vulnerability' },
            { value: 'blocked', text: 'Attack blocked by WAF' },
            { value: 'error', text: 'Query syntax error' },
            { value: 'safe', text: 'Parameterized query prevented attack' }
        ],
        correct: 'sqli_success',
        mitre: 'T1190',
        explanation: '💉 SQLi Success: HTTP 200 after UNION SELECT = query executed successfully, app returned passwords! Attack: Close string with \', add UNION to append malicious SELECT, comment out rest with --. Status codes: 200 (success - vulnerable!), 500 (error - may still be vulnerable), 403 (WAF blocked). Detection: WAF/IDS signatures, log analysis (UNION, SELECT, \', --, OR 1=1), anomaly in query params. Investigation: Check if passwords actually leaked (DB audit logs), identify affected users. Response: Take app offline, patch (use parameterized queries/ORMs), rotate all user passwords, notify breach. OWASP A03:2021. MITRE: T1190 (Exploit Public-Facing Application).'
    },
    {
        id: 'log62',
        title: 'Active Directory DCSync Attack',
        points: 9,
        question: 'DC EventID 4662: ObjectType=DS-Replication-Get-Changes-All, SubjectUser=jsmith, TargetObject=domain. What attack?',
        type: 'radio',
        options: [
            { value: 'dcsync', text: 'DCSync attack - credential dumping' },
            { value: 'backup', text: 'Domain controller backup' },
            { value: 'replication', text: 'Normal AD replication' },
            { value: 'restore', text: 'AD restore operation' }
        ],
        correct: 'dcsync',
        mitre: 'T1003.006',
        explanation: '🎫 DCSync: Mimikatz attack that impersonates DC to request password hashes. EventID 4662 with DS-Replication-Get-Changes(-All) = replication permissions used. Attack: 1) Compromise Domain Admin or user with DCSync rights, 2) Run mimikatz lsadump::dcsync, 3) Extract krbtgt hash → Golden Ticket, or all user hashes → offline cracking. Detection: 4662 events where Subject ≠ DC computer account, especially from workstations/servers. Prevention: Audit "Replicating Directory Changes" permissions (should be DCs only), monitor with SIEM, honeypot accounts. Red flag: jsmith (regular user) should NEVER have replication rights. Action: Revoke permissions, assume full domain compromise, reset krbtgt twice, investigate how jsmith got DA. MITRE: T1003.006 (DCSync).'
    },
    {
        id: 'log63',
        title: 'Web Application Session Hijacking',
        points: 7,
        question: 'App logs: User=alice, SessionID=abc123, IP changes from 192.168.1.5 to 203.0.113.50 mid-session. What risk?',
        type: 'radio',
        options: [
            { value: 'hijack', text: 'Session hijacking - stolen session cookie' },
            { value: 'roaming', text: 'User switched networks (WiFi to cellular' },
            { value: 'proxy', text: 'Corporate proxy rotation' },
            { value: 'normal', text: 'Normal behavior for mobile users' }
        ],
        correct: 'hijack',
        mitre: 'T1539',
        explanation: '🍪 Session Hijacking: SessionID should be tied to source IP. IP change mid-session = cookie stolen (XSS, network sniffing, malware). Internal→External IP especially suspicious (192.168→203.0). Attack: Steal cookie → replay in attacker browser → impersonate user (no password needed). Detection: IP geofencing, device fingerprinting, bind session to IP+User-Agent. Legitimate IP changes: Mobile networks, VPN connects, NAT changes. Prevention: 1) **Regenerate session on IP change** (or require re-auth), 2) **HttpOnly + Secure flags**, 3) **Short session timeout**, 4) **MFA for sensitive actions**. Mobile users: Accept IP changes but log/alert, use device tokens. MITRE: T1539 (Steal Web Session Cookie).'
    },
    {
        id: 'log64',
        title: 'Suricata Eve.json Alert Aggregation',
        points: 8,
        question: 'Suricata eve.json: 10,000 alerts "ET SCAN Nmap Scripting Engine" from 45.33.32.156 in 5 minutes. Proper response?',
        type: 'radio',
        options: [
            { value: 'block_source', text: 'Block source IP - active scanning targeting network' },
            { value: 'ignore', text: 'Ignore - likely false positive' },
            { value: 'update', text: 'Update Suricata signatures' },
            { value: 'investigate_dest', text: 'Investigate only if alerts persist 24+ hours' }
        ],
        correct: 'block_source',
        mitre: 'T1046',
        explanation: '🚨 Signature Flooding: 10K alerts in 5 min = active attack, not false positive. ET SCAN Nmap = Suricata detected nmap NSE (Nmap Scripting Engine) fingerprints. Response: 1) **Block source IP** at perimeter firewall, 2) Check what ports/services scanned (eve.json dest_port), 3) Vulnerability assessment (are scanned services exposed?), 4) Threat intel lookup (45.33.32.156 - known scanner?), 5) Monitor for follow-up exploitation attempts. Alert fatigue mitigation: Aggregate by src_ip, use thresholds (>100 alerts/5min = single high-severity incident), suppress after initial alert. Don\'t ignore: Reconnaissance precedes exploitation. MITRE: T1046 (Network Service Discovery/Scanning).'
    },
    {
        id: 'log65',
        title: 'Proxy Log Data Exfiltration',
        points: 8,
        question: 'Proxy: user=jdoe, POST to pastebin.com, size=450MB, time=02:30 AM. What activity?',
        type: 'radio',
        options: [
            { value: 'exfil', text: 'Data exfiltration to public paste site' },
            { value: 'backup', text: 'Personal file backup' },
            { value: 'sharing', text: 'Code sharing for collaboration' },
            { value: 'normal', text: 'Normal developer activity' }
        ],
        correct: 'exfil',
        mitre: 'T1567.001',
        explanation: '📤 Data Exfil: Pastebin normally hosts text snippets (<1MB). 450MB POST = file upload/exfiltration. Red flags: 1) **Off-hours** (02:30 AM), 2) **Massive size** (450MB), 3) **Public site** (data now exposed). Exfil channels: Pastebin, GitHub Gist, Google Drive, Dropbox, DNS tunneling, steganography. Detection: DLP monitoring uploads to cloud/paste sites, baseline normal data volumes, alert on off-hours large transfers. Investigation: What data? Access DB audit logs, check file server access, interview user. Prevention: Block paste sites, data classification + encryption, USB/cloud controls. Insider threat indicators: Off-hours, resignation/termination pending, financial stress. MITRE: T1567.001 (Exfiltration to Cloud Storage).'
    },
    {
        id: 'log66',
        title: 'Sysmon Event ID 8 Remote Thread',
        points: 9,
        question: 'Sysmon EventID 8: SourceImage=malware.exe, TargetImage=lsass.exe, GrantedAccess=0x1FFFFF. What technique?',
        type: 'radio',
        options: [
            { value: 'credential_dump', text: 'Credential dumping via LSASS memory access' },
            { value: 'normal', text: 'Normal process interaction' },
            { value: 'antivirus', text: 'Antivirus scan of LSASS' },
            { value: 'update', text: 'Windows security update' }
        ],
        correct: 'credential_dump',
        mitre: 'T1003.001',
        explanation: '🔑 LSASS Dump: EventID 8 (CreateRemoteThread) = process injection. TargetImage=lsass.exe + GrantedAccess=0x1FFFFF (PROCESS_ALL_ACCESS) = Mimikatz/credential dumper reading LSASS memory to extract passwords/hashes. Attack: 1) Malware gains admin/SYSTEM, 2) Opens handle to lsass.exe, 3) Reads memory containing credentials. Detection: Sysmon ID 8, ID 10 (ProcessAccess), AccessMask monitoring. Legitimate: Some AV/EDR access LSASS (whitelist known tools). Prevention: Credential Guard (virtualization-based security), PPL (Protected Process Light) for LSASS, alert on any non-system access. Tools: Mimikatz, ProcDump, Sysinternals ProcDump. Investigation: Memory forensics, check for dumped files. MITRE: T1003.001 (LSASS Memory).'
    },
    {
        id: 'log67',
        title: 'DNS Tunneling Byte Analysis',
        points: 8,
        question: 'DNS queries: avg length 45 chars, NXDOMAIN rate 95%, entropy 4.8, request rate 100/min from single host. What attack?',
        type: 'radio',
        options: [
            { value: 'tunnel', text: 'DNS tunneling exfiltration' },
            { value: 'dga', text: 'DGA malware only' },
            { value: 'normal', text: 'Normal DNS resolution' },
            { value: 'misconfigured', text: 'Misconfigured DNS client' }
        ],
        correct: 'tunnel',
        mitre: 'T1071.004',
        explanation: '🕳️ DNS Tunnel Detection: Combines multiple indicators: 1) **High entropy** (4.8 = random-looking, encoded data in subdomain), 2) **Long queries** (45 chars = max data per query), 3) **High NXDOMAIN** (tunnel server only responds to encoded queries), 4) **High frequency** (100/min = continuous exfil). DGA vs Tunnel: DGA seeks working C2 (eventually succeeds, then normal traffic), Tunnel maintains constant high-volume queries. Tools: Iodine, dnscat2, DNS2TCP. Detection: Entropy analysis, query length distribution, traffic patterns. Example query: aGVsbG8.d29ybGQ.attacker.com (base64-encoded hello.world). Prevention: Block unusual TLDs, rate limiting, inspect query content. MITRE: T1071.004 (DNS).'
    },
    {
        id: 'log68',
        title: 'Firewall State Table Exhaustion',
        points: 7,
        question: 'Firewall logs: 50,000 SYN packets to port 80, no ACK responses, state table 98% full. What attack?',
        type: 'radio',
        options: [
            { value: 'syn_flood', text: 'SYN flood DDoS attack' },
            { value: 'port_scan', text: 'Port scanning activity' },
            { value: 'normal', text: 'Normal high traffic period' },
            { value: 'routing', text: 'Routing loop issue' }
        ],
        correct: 'syn_flood',
        mitre: 'T1499.002',
        explanation: '⚡ SYN Flood: TCP handshake attack. Attacker sends SYN, firewall allocates state entry awaiting SYN-ACK-ACK completion, attacker never sends ACK → half-open connections exhaust state table → legitimate traffic dropped. Indicators: 1) **Massive SYN count**, 2) **No corresponding ACK**, 3) **State table near capacity**, 4) Spoofed source IPs (can\'t receive SYN-ACK). Impact: DoS - firewall can\'t track new connections. Mitigation: 1) **SYN cookies** (stateless handshake), 2) **Rate limiting** per source, 3) **Shorter timeouts** for half-open, 4) **Increase state table size**, 5) **Upstream DDoS mitigation** (Cloudflare, Akamai). Different from SYN scan: Scan tests one port at a time, flood overwhelms with volume. MITRE: T1499.002 (Service Exhaustion Flood).'
    },
    {
        id: 'log69',
        title: 'SIEM Correlation Rule Logic',
        points: 8,
        question: 'Rule: (EventID=4625 count>5 in 10min) AND (EventID=4624 LogonType=10) within 2min. What does this detect?',
        type: 'radio',
        options: [
            { value: 'rdp_brute_success', text: 'RDP brute force with successful login' },
            { value: 'normal_login', text: 'Normal user login pattern' },
            { value: 'password_spray', text: 'Password spray only' },
            { value: 'lockout', text: 'Account lockout event' }
        ],
        correct: 'rdp_brute_success',
        mitre: 'T1110',
        explanation: '🎯 Correlation Logic: Part 1: EventID 4625 (failed logon) count>5 in 10min = brute force attempt. Part 2: Followed by EventID 4624 (success) with LogonType=10 (RemoteInteractive = RDP) within 2 min = attacker succeeded! This is high-fidelity alert: Brute force + success = confirmed compromise. Action: Immediate response (disable account, terminate session, investigate source IP). Single event limitations: 4625 alone = might be user typo, 4624 alone = normal login. **Correlation creates context**. SIEM value: Time-based sequences, cross-event patterns, reduce false positives. Other useful correlations: (New user created) + (added to admins) + (lateral movement), (High data transfer) + (off hours) + (to external IP). MITRE: T1110 (Brute Force).'
    },
    {
        id: 'log70',
        title: 'JSON Log Parsing for Threat Hunting',
        points: 8,
        question: 'CloudTrail JSON: eventName:"PutBucketPolicy", requestParameters.bucketPolicy contains "Principal":"*". What misconfiguration?',
        type: 'radio',
        options: [
            { value: 'public_bucket', text: 'S3 bucket made publicly accessible' },
            { value: 'encryption', text: 'Encryption policy updated' },
            { value: 'versioning', text: 'Versioning configuration change' },
            { value: 'safe', text: 'Normal secure configuration' }
        ],
        correct: 'public_bucket',
        mitre: 'T1530',
        explanation: '☁️ Public S3 Bucket: PutBucketPolicy with "Principal":"*" = anyone on internet can access bucket. Attack/mistake: 1) Insider error, 2) Compromised creds make bucket public → data breach, 3) Cryptomining (public buckets serving malware). Detection: Parse CloudTrail JSON for PutBucketPolicy/PutBucketAcl events, check if Principal=* or AllUsers, alert immediately. AWS tools: Trusted Advisor, Access Analyzer, S3 Block Public Access (preventive). Real breaches: Capital One (SSRF → cloud metadata → PutBucketPolicy), countless public bucket leaks (credentials, PII, source code). Hunt query: eventName:PutBucket* AND (Principal:* OR AllUsers). Prevention: SCPs blocking public access, least privilege IAM. MITRE: T1530 (Data from Cloud Storage).'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = logsExtended;
}
