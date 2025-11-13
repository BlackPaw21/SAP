/**
 * Extended Security Infrastructure Questions (dev51-100)
 * Lazy-loaded when user clicks "Load More Questions"
 *
 * Current Status: dev51-60 complete (10 questions)
 * Base questions (dev1-50) are in questions_data.js
 */

const devicesExtended = [
    {
        id: 'dev51',
        title: 'SIEM Correlation Rule Design',
        points: 12,
        question: 'SIEM detects: Failed login (Event 4625) from IP X, then successful login (4624) from same IP within 5 minutes. What attack pattern?',
        type: 'radio',
        options: [
            { value: 'brute_success', text: 'Successful brute force attack' },
            { value: 'failed_only', text: 'Failed login attempt only' },
            { value: 'normal', text: 'Normal user behavior (typo then correct)' },
            { value: 'enumeration', text: 'Username enumeration' },
            { value: 'dos', text: 'Denial of service attack' }
        ],
        correct: 'brute_success',
        explanation: '🎯 SIEM Correlation: Simple failed login = noisy alert. Failed→Success pattern = likely successful brute force/credential stuffing. Advanced rules: 1) Threshold: >5 failures before success, 2) Time window: 5-60 minutes, 3) **Geo-velocity**: Login from US then China in 1 hour (impossible travel), 4) **New device**: Success from never-before-seen IP/User-Agent. SIEM platforms: Splunk, QRadar, Sentinel. Tune to reduce false positives (legitimate typos). Interview: "Design SIEM use case for account compromise."'
    },
    {
        id: 'dev52',
        title: 'IDS vs IPS Placement',
        points: 10,
        question: 'What is the primary difference in network placement between IDS and IPS?',
        type: 'radio',
        options: [
            { value: 'inline', text: 'IPS is inline (blocks traffic), IDS is passive (monitors copy)' },
            { value: 'speed', text: 'IDS is faster than IPS' },
            { value: 'cost', text: 'IPS is more expensive' },
            { value: 'accuracy', text: 'IDS is more accurate' },
            { value: 'same', text: 'No difference in placement' }
        ],
        correct: 'inline',
        explanation: '🔀 IDS vs IPS Placement: **IDS (Intrusion Detection System)**: Passive monitoring via SPAN/mirror port. Alerts only, no blocking. Cannot be bypassed but can\'t prevent attacks. **IPS (Intrusion Prevention System)**: Inline deployment (all traffic flows through). Can block malicious traffic in real-time. Risk: False positive blocks legitimate traffic (availability impact). Hybrid: IDS mode first (tune rules), then enable IPS blocking. Vendors: Snort (both modes), Suricata, Palo Alto Threat Prevention. Interview: "When would you use IDS vs IPS?"'
    },
    {
        id: 'dev53',
        title: 'EDR vs Antivirus',
        points: 11,
        question: 'What capabilities does EDR (Endpoint Detection & Response) provide beyond traditional antivirus?',
        type: 'checkbox',
        options: [
            { value: 'behavior', text: 'Behavioral analysis and anomaly detection' },
            { value: 'forensics', text: 'Forensic data collection and timeline analysis' },
            { value: 'response', text: 'Remote response actions (isolate, kill process)' },
            { value: 'threat_hunt', text: 'Threat hunting and IoC searching across fleet' },
            { value: 'faster_scan', text: 'Just faster virus scanning' },
            { value: 'cheaper', text: 'Lower cost than AV' }
        ],
        correct: ['behavior', 'forensics', 'response', 'threat_hunt'],
        explanation: '🛡️ EDR Capabilities: Traditional AV = signature-based detection. **EDR adds**: 1) **Behavioral detection**: Identifies malicious behavior (not just signatures), detects fileless malware, 2) **Forensics**: Process tree, registry changes, network connections, file modifications, 3) **Response**: Remote shell access, isolate endpoint, kill processes, 4) **Threat hunting**: Search all endpoints for IoCs, retrospective detection. Vendors: CrowdStrike Falcon, SentinelOne, Microsoft Defender ATP, Carbon Black. Modern: XDR (Extended Detection Response) = EDR + network + cloud. Interview: "EDR detection techniques."'
    },
    {
        id: 'dev54',
        title: 'SOAR Platform Benefits',
        points: 12,
        question: 'What is the primary purpose of SOAR (Security Orchestration, Automation, Response)?',
        type: 'radio',
        options: [
            { value: 'automate', text: 'Automate repetitive security tasks and incident response workflows' },
            { value: 'replace_siem', text: 'Replace SIEM entirely' },
            { value: 'antivirus', text: 'Provide better antivirus protection' },
            { value: 'compliance', text: 'Generate compliance reports only' },
            { value: 'firewall', text: 'Replace firewall functionality' }
        ],
        correct: 'automate',
        explanation: '🤖 SOAR: Automates security operations. Use cases: 1) **Phishing response**: Email arrives→extract IoCs→VirusTotal check→block sender→quarantine email→ticket created (0 human interaction), 2) **Malware containment**: Alert→isolate endpoint→block C2 domain→collect forensics, 3) **Threat intel enrichment**: Alert→enrich with ThreatConnect→calculate risk score. Components: Playbooks (workflows), integrations (APIs to other tools), case management. Vendors: Palo Alto XSOAR, Splunk Phantom, IBM Resilient. Reduces analyst burnout (Tier 1 automation). Interview: "Design SOAR playbook for ransomware."'
    },
    {
        id: 'dev55',
        title: 'Honeypot Deployment Strategy',
        points: 11,
        question: 'High-interaction honeypot vs low-interaction honeypot - what is the key difference?',
        type: 'radio',
        options: [
            { value: 'interaction', text: 'High-interaction = real OS/services, low-interaction = simulated' },
            { value: 'cost', text: 'High-interaction is cheaper' },
            { value: 'speed', text: 'Low-interaction is slower' },
            { value: 'detection', text: 'Low-interaction detects more attacks' },
            { value: 'same', text: 'No significant difference' }
        ],
        correct: 'interaction',
        explanation: '🍯 Honeypot Types: **Low-interaction**: Simulates services (fake SSH, FTP). Safe (no real vulnerability), limited attacker engagement. Use: Detect scanning, capture automated attacks. Tools: Honeyd, Cowrie. **High-interaction**: Real vulnerable systems. Risk: Attacker could pivot to production (requires strong isolation). Benefits: Capture full attack chains, malware samples, TTPs. Use: Research, APT analysis. Tools: Full VMs with vulnerabilities. **Honeynet**: Network of honeypots. Honeytoken: Fake credentials. Interview: "When to use low vs high interaction honeypots?"'
    },
    {
        id: 'dev56',
        title: 'SIEM Data Retention',
        points: 10,
        question: 'Organization must retain security logs for 1 year for compliance but SIEM storage is expensive. What is the best approach?',
        type: 'radio',
        options: [
            { value: 'tiered', text: 'Hot storage (90 days searchable) + cold storage (archived 1 year)' },
            { value: 'delete', text: 'Delete logs after 30 days to save cost' },
            { value: 'all_hot', text: 'Keep all 1 year in hot/searchable storage' },
            { value: 'sampling', text: 'Only store 10% sample of logs' },
            { value: 'external', text: 'Store all logs externally (no SIEM)' }
        ],
        correct: 'tiered',
        explanation: '📊 SIEM Storage Tiers: **Hot storage**: Fast search (SSD), expensive, keep recent logs (30-90 days). **Warm storage**: Slower search, medium cost (180 days). **Cold storage**: Archived (S3, tape), must rehydrate to search, cheap. Compliance: Many regulations require 1 year retention (PCI-DSS, HIPAA, GDPR). Strategy: Hot for active investigation, cold for compliance/forensics. Splunk SmartStore, Sentinel tiering, QRadar data archiving. Cost: Hot=$$$, Cold=$. Interview: "SIEM architecture for cost optimization."'
    },
    {
        id: 'dev57',
        title: 'Network TAP vs SPAN',
        points: 11,
        question: 'Security team deploying IDS. Network TAP vs SPAN port - which is more reliable for packet capture?',
        type: 'radio',
        options: [
            { value: 'tap', text: 'TAP - passive hardware, no packet loss, sees all traffic' },
            { value: 'span', text: 'SPAN - better performance and flexibility' },
            { value: 'same', text: 'Both are equally reliable' },
            { value: 'depends', text: 'Depends on network speed' },
            { value: 'neither', text: 'Both unreliable for IDS' }
        ],
        correct: 'tap',
        explanation: '🔍 TAP vs SPAN: **Network TAP (Test Access Point)**: Physical device inline, optical splitter or copper tap. Benefits: 1) **No packet loss**: Dedicated monitoring, 2) **Always on**: Even if switch fails, 3) **Full duplex**: Sees both directions, 4) **No overhead**: Switch performance unaffected. Cons: Cost, physical installation. **SPAN (Port Mirroring)**: Switch copies traffic to monitor port. Cons: 1) **Packet drops**: Under load, monitoring is lower priority, 2) **No switch errors**: Won\'t see CRC errors, 3) **Oversubscription**: Can miss traffic. Best practice: TAP for critical monitoring. Interview: "IDS deployment architecture."'
    },
    {
        id: 'dev58',
        title: 'Threat Intelligence Platforms',
        points: 12,
        question: 'What is the primary purpose of a Threat Intelligence Platform (TIP)?',
        type: 'radio',
        options: [
            { value: 'aggregate', text: 'Aggregate, normalize, and enrich threat intel from multiple sources' },
            { value: 'antivirus', text: 'Replace antivirus with better detection' },
            { value: 'firewall', text: 'Act as next-gen firewall' },
            { value: 'siem', text: 'Replace SIEM functionality' },
            { value: 'ids', text: 'Intrusion detection only' }
        ],
        correct: 'aggregate',
        explanation: '🧠 Threat Intelligence Platform: Centralize threat intel management. Functions: 1) **Ingest**: Collect from OSINT (abuse.ch, Alienvault OTX), commercial feeds (Recorded Future, ThreatConnect), ISACs, internal IoCs, 2) **Normalize**: STIX/TAXII formats, deduplicate, 3) **Enrich**: Context (malware family, campaign, TTPs), scoring (confidence, severity), 4) **Distribute**: Push to SIEM, firewall, EDR, 5) **Analyst workflow**: Investigation, pivoting. Vendors: ThreatConnect, Anomali, MISP (open source). Integration with SOAR for automated response. Interview: "Threat intel lifecycle and operationalization."'
    },
    {
        id: 'dev59',
        title: 'Sysmon Event ID Monitoring',
        points: 13,
        question: 'Which Sysmon Event IDs indicate potential malicious activity? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'eid1', text: 'Event ID 1 - Process creation (monitor suspicious processes)' },
            { value: 'eid3', text: 'Event ID 3 - Network connection (C2 communication)' },
            { value: 'eid10', text: 'Event ID 10 - Process access (credential dumping from lsass)' },
            { value: 'eid13', text: 'Event ID 13 - Registry modification (persistence)' },
            { value: 'eid22', text: 'Event ID 22 - DNS query (C2 domain resolution)' },
            { value: 'all_safe', text: 'All Sysmon events are safe/benign' }
        ],
        correct: ['eid1', 'eid3', 'eid10', 'eid13', 'eid22'],
        explanation: '📡 Sysmon Monitoring: Sysmon = enhanced Windows event logging. Key Event IDs: **1 (Process Create)**: powershell.exe -enc (encoded), unusual parent-child (Word→cmd), **3 (Network)**: C2 IPs, Tor, unusual ports, **7 (Module Load)**: DLL injection, **10 (Process Access)**: Access to lsass.exe = credential dumping, **13 (Registry)**: Run keys for persistence, **22 (DNS)**: DGA domains, tunneling. Config: SwiftOnSecurity config (good baseline). Forward to SIEM for detection rules. MITRE ATT&CK mapping. Interview: "Essential Sysmon events for threat detection."'
    },
    {
        id: 'dev60',
        title: 'Deception Technology',
        points: 11,
        question: 'Organization deploys fake admin credentials, fake file shares, fake database servers throughout network. What is this strategy?',
        type: 'radio',
        options: [
            { value: 'deception', text: 'Deception technology / active defense' },
            { value: 'honeypot', text: 'Traditional honeypot only' },
            { value: 'misconfiguration', text: 'Security misconfiguration' },
            { value: 'backup', text: 'Backup infrastructure' },
            { value: 'testing', text: 'Penetration testing setup' }
        ],
        correct: 'deception',
        explanation: '🎭 Deception Technology: Distributed decoys and breadcrumbs throughout production network. vs Traditional honeypot (isolated). **Deception types**: 1) **Honeytokens**: Fake AWS keys in code, fake DB credentials, 2) **Honeycredentials**: Fake admin accounts, 3) **Honey files**: Fake "passwords.xlsx", 4) **Honey shares**: Fake file servers, 5) **Honey services**: Fake databases, RDP. Any interaction = high-confidence alert (no false positives from real users). Slow attackers, gather intelligence, alert on lateral movement. Vendors: Attivo, Illusive, TrapX. Interview: "Deception vs detection."'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = devicesExtended;
}
