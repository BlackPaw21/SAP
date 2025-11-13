/**
 * Extended Log Analysis Questions (log51-100)
 * Lazy-loaded when user clicks "Load More Questions"
 *
 * Current Status: log51-60 complete (10 questions)
 * Base questions (log1-50) are in questions_data.js
 */

const logsExtended = [
    {
        id: 'log51',
        title: 'Windows Event 4648 Analysis',
        points: 12,
        question: 'Event ID 4648 (Logon with explicit credentials) shows user Alice logged in but different credentials used for network share. What does this indicate?',
        type: 'radio',
        options: [
            { value: 'runas', text: 'RunAs / credential theft - using someone else\'s credentials' },
            { value: 'normal', text: 'Normal multi-user system behavior' },
            { value: 'error', text: 'System error or misconfiguration' },
            { value: 'upgrade', text: 'System upgrade in progress' },
            { value: 'backup', text: 'Backup operation running' }
        ],
        correct: 'runas',
        explanation: '🔐 Event 4648: "A logon was attempted using explicit credentials." Occurs when: 1) **RunAs** (/netonly for network auth), 2) **net use** with different credentials, 3) **Credential theft**: Alice logged in but using Bob\'s creds for lateral movement (Pass-the-Hash aftermath). Correlation: Look for 4648 from unusual accounts, accessing admin shares, followed by suspicious process creation. Paired with Event 4624 (successful logon). Attacker pattern: Compromise Alice → steal Bob (admin) creds → 4648 using Bob\'s creds → pivot. Interview: "Critical Windows security events."'
    },
    {
        id: 'log52',
        title: 'Apache Access Log Analysis',
        points: 11,
        question: 'Apache access log: 192.168.1.50 - - [01/Jan/2024:10:15:30] "GET /admin.php?cmd=whoami HTTP/1.1" 200 512. What attack is indicated?',
        type: 'radio',
        options: [
            { value: 'rce', text: 'Remote Code Execution attempt via command injection' },
            { value: 'sqli', text: 'SQL Injection attack' },
            { value: 'xss', text: 'Cross-Site Scripting' },
            { value: 'normal', text: 'Normal administrative access' },
            { value: 'brute_force', text: 'Brute force attack' }
        ],
        correct: 'rce',
        explanation: '💥 Command Injection IoC: URL parameter "cmd=whoami" = attempt to execute shell command. Response 200 = request succeeded (potential RCE). Attack: Vulnerable PHP code: system($_GET["cmd"]). Red flags in logs: 1) Shell commands: whoami, cat /etc/passwd, wget, curl, 2) Path traversal: ../.., 3) SQL keywords: UNION, SELECT, 4) Script tags: <script>. Defense: Input validation, WAF, log monitoring. Tools: GoAccess, AWStats for log analysis. Interview: "Web server log forensics."'
    },
    {
        id: 'log53',
        title: 'DNS Query Anomaly Detection',
        points: 13,
        question: 'DNS logs show workstation querying 50 random-looking domains with high entropy in 1 minute, all returning NXDOMAIN. What is likely occurring?',
        type: 'radio',
        options: [
            { value: 'dga', text: 'Domain Generation Algorithm (DGA) malware C2 communication' },
            { value: 'normal', text: 'Normal user browsing behavior' },
            { value: 'update', text: 'Software update checking multiple CDNs' },
            { value: 'dns_error', text: 'DNS server misconfiguration' },
            { value: 'fast_browsing', text: 'User browsing very quickly' }
        ],
        correct: 'dga',
        explanation: '🎲 DGA Detection in DNS Logs: Indicators: 1) **High NXDOMAIN rate**: Most domains don\'t exist, 2) **Entropy**: Random-looking (xk7dm3vlq.com vs google.com), 3) **Volume**: Hundreds/thousands of queries, 4) **Pattern**: Algorithmic generation, similar length/structure. Malware families: Conficker, Cryptolocker, Emotet, Qakbot. Analysis: Shannon entropy calculation, character distribution, TLD analysis. SIEM rule: >20 NXDOMAIN in 5 minutes from single host. Tools: DGA detection ML models, passive DNS. Interview: "DNS-based threat detection."'
    },
    {
        id: 'log54',
        title: 'Syslog Severity Levels',
        points: 9,
        question: 'Syslog severity 0 vs severity 7 - what is the difference?',
        type: 'radio',
        options: [
            { value: 'emergency_debug', text: 'Severity 0 = Emergency (system unusable), 7 = Debug (diagnostic info)' },
            { value: 'same', text: 'Both indicate errors' },
            { value: 'reverse', text: '0 = Debug, 7 = Emergency' },
            { value: 'warnings', text: 'Both are warning levels' },
            { value: 'informational', text: 'Both are informational' }
        ],
        correct: 'emergency_debug',
        explanation: '📊 Syslog Severity Levels (RFC 5424): **0 Emergency**: System unusable (kernel panic). **1 Alert**: Immediate action needed. **2 Critical**: Critical conditions. **3 Error**: Error conditions. **4 Warning**: Warning conditions. **5 Notice**: Normal but significant. **6 Informational**: Informational messages. **7 Debug**: Debug-level messages. SIEM filtering: Alert on 0-3, monitor 4-5, discard 7 (too verbose). Network devices, Linux, firewalls use syslog. Interview: "Log aggregation and filtering."'
    },
    {
        id: 'log55',
        title: 'Web Application Firewall Logs',
        points: 12,
        question: 'WAF blocks request with SQL injection signature. HTTP response code in logs?',
        type: 'radio',
        options: [
            { value: '403', text: '403 Forbidden - WAF blocked request' },
            { value: '200', text: '200 OK - request succeeded' },
            { value: '404', text: '404 Not Found' },
            { value: '500', text: '500 Internal Server Error' },
            { value: '302', text: '302 Redirect' }
        ],
        correct: '403',
        explanation: '🛡️ WAF Response Codes: **403 Forbidden** = WAF actively blocked malicious request (SQL injection, XSS, path traversal). **406 Not Acceptable** (some WAFs). **200 OK** = request reached backend (WAF in monitor mode or didn\'t detect). WAF logs contain: Rule ID, attack type, source IP, blocked payload, risk score. False positives common = tuning needed. Vendors: Cloudflare, AWS WAF, F5, ModSecurity. Modern: WAF + RASP (Runtime Application Self-Protection). Interview: "WAF deployment and tuning."'
    },
    {
        id: 'log56',
        title: 'Failed Login Threshold',
        points: 10,
        question: 'How many failed login attempts typically indicate brute force vs. user error?',
        type: 'radio',
        options: [
            { value: 'threshold', text: '5-10 attempts = likely brute force, 1-3 = possibly user error' },
            { value: 'one', text: '1 failed attempt = definitely attack' },
            { value: 'unlimited', text: 'Any number could be normal user behavior' },
            { value: 'hundred', text: 'Need 100+ attempts to confirm attack' },
            { value: 'no_correlation', text: 'Count doesn\'t indicate attack type' }
        ],
        correct: 'threshold',
        explanation: '🔐 Failed Login Analysis: **User error**: 1-3 attempts (typo, Caps Lock, expired password). **Brute force**: 5+ rapid attempts from same IP, password spray (1 attempt × many accounts), credential stuffing. Advanced detection: 1) **Time window**: 5 failures in 5 minutes, 2) **Geo-impossible**: Login from US then China, 3) **User-Agent**: Automated tools, 4) **Success after failures**: Brute force succeeded. SIEM correlation: Event 4625 (failed) → 4624 (success) = investigate. Lockout policies: 5-10 attempts. Interview: "Authentication attack detection."'
    },
    {
        id: 'log57',
        title: 'Proxy Log Data Exfiltration',
        points: 13,
        question: 'Proxy logs show employee uploaded 50GB to file-sharing site in 1 hour. Which fields are most useful for investigation?',
        type: 'checkbox',
        options: [
            { value: 'url', text: 'Destination URL (which file-sharing service)' },
            { value: 'user', text: 'Username (which employee)' },
            { value: 'bytes', text: 'Bytes sent (volume of data uploaded)' },
            { value: 'time', text: 'Timestamp (when exfiltration occurred)' },
            { value: 'color', text: 'Browser color theme' }
        ],
        correct: ['url', 'user', 'bytes', 'time'],
        explanation: '📤 Data Exfiltration Analysis: Key proxy log fields: 1) **URL**: Destination (Dropbox, Mega, pastebin, GitHub), 2) **Username**: Who (insider threat, compromised account), 3) **Bytes sent**: Volume (50GB = massive exfil), 4) **Time**: Off-hours = suspicious, 5) **User-Agent**: Automated tools vs browser, 6) **Action**: POST/PUT = upload. DLP integration: Tag sensitive files. Patterns: Sudden large uploads, cloud storage, encrypted tunnels (HTTPS = can\'t see content). Baseline: Normal user upload patterns. Interview: "DLP and exfiltration detection."'
    },
    {
        id: 'log58',
        title: 'Firewall Denied Logs',
        points: 11,
        question: 'Firewall logs show thousands of DENY entries from internal host scanning ports. What should SOC analyst do?',
        type: 'radio',
        options: [
            { value: 'investigate', text: 'Investigate immediately - potential compromised host or insider threat' },
            { value: 'ignore', text: 'Ignore - denied traffic is not a concern' },
            { value: 'block_ip', text: 'Just block the source IP' },
            { value: 'wait', text: 'Wait for user to report issues' },
            { value: 'reboot', text: 'Reboot firewall to clear logs' }
        ],
        correct: 'investigate',
        explanation: '🚨 Outbound Scanning IoC: Internal host scanning = malware reconnaissance or attacker pivot. Denied = firewall blocked but indicates compromise. Investigate: 1) **EDR logs**: What process initiated scans?, 2) **User interview**: Authorized security scan?, 3) **Network baseline**: Normal for this host?, 4) **Other IoCs**: C2 connections, suspicious processes. Port scanning tools: nmap, masscan. Malware behavior: Worms scan for propagation, ransomware scans for file shares. Response: Isolate host, forensic analysis. Don\'t ignore denied traffic = shows attacker intent. Interview: "Firewall log analysis for threat hunting."'
    },
    {
        id: 'log59',
        title: 'CloudTrail AWS API Logging',
        points: 13,
        question: 'AWS CloudTrail log shows "DeleteBucket" API call at 2 AM from unfamiliar IP. What should trigger immediate investigation?',
        type: 'checkbox',
        options: [
            { value: 'destructive', text: 'Destructive operation (DeleteBucket)' },
            { value: 'time', text: 'Off-hours timing (2 AM)' },
            { value: 'ip', text: 'Unfamiliar source IP address' },
            { value: 'user', text: 'User identity and permissions' },
            { value: 'nothing', text: 'Normal cloud maintenance operation' }
        ],
        correct: ['destructive', 'time', 'ip', 'user'],
        explanation: '☁️ CloudTrail Forensics: AWS API activity logging. Red flags: **Destructive ops**: DeleteBucket, TerminateInstances, DetachRole, **Off-hours**: Unusual time for admin work, **Unknown IP**: Not corporate IP/VPN, **Privilege escalation**: AssumeRole, AttachUserPolicy, **Region**: Unexpected region. Investigation: 1) Identity (IAM user/role, access key), 2) Source IP (VPN? Tor? Foreign country?), 3) Other actions by same identity, 4) Success/failure. Response: Rotate compromised keys, restore from backup. Similar: Azure Activity Log, GCP Cloud Audit. Interview: "Cloud security monitoring."'
    },
    {
        id: 'log60',
        title: 'Log Retention Compliance',
        points: 10,
        question: 'PCI-DSS requires how long security log retention?',
        type: 'radio',
        options: [
            { value: 'one_year', text: 'Minimum 1 year (3 months online, 9 months archived)' },
            { value: 'thirty_days', text: '30 days only' },
            { value: 'six_months', text: '6 months' },
            { value: 'forever', text: 'Forever (no deletion allowed)' },
            { value: 'no_requirement', text: 'PCI-DSS has no log retention requirement' }
        ],
        correct: 'one_year',
        explanation: '📜 Log Retention Requirements: **PCI-DSS 10.7**: 1 year minimum (3 months immediately available online, 9 months archived). **HIPAA**: 6 years. **SOX**: 7 years. **GDPR**: As needed for purpose (but data minimization). **FISMA**: 90 days online + archives. Use cases: Forensic analysis (breach 6 months ago), compliance audits, trend analysis. Storage tiers: Hot (SIEM fast search), warm (slower), cold (S3, tape). Balance: Compliance vs cost. Interview: "Security logging compliance requirements."'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = logsExtended;
}
