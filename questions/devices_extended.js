/**
 * Extended Security Infrastructure Questions (dev51-70)
 * Lazy-loaded when user clicks "Load More Questions"
 */

const devicesExtended = [
    {
        id: 'dev51',
        title: 'SOAR Platform Capabilities',
        points: 9,
        question: 'SOAR (Security Orchestration, Automation, and Response) platforms provide which capabilities? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'playbooks', text: 'Automated playbooks for incident response' },
            { value: 'integration', text: 'Integration with 50+ security tools via APIs' },
            { value: 'case_management', text: 'Case management and ticketing' },
            { value: 'threat_intel', text: 'Threat intelligence aggregation and enrichment' },
            { value: 'antivirus', text: 'Built-in antivirus scanning' },
            { value: 'firewall_rules', text: 'Native firewall policy management' }
        ],
        correct: ['playbooks', 'integration', 'case_management', 'threat_intel'],
        explanation: '🤖 SOAR Benefits: Automate repetitive SOC tasks. 1) **Playbooks**: If (phishing alert) → Extract IOCs → Query VirusTotal → Block sender → Quarantine email → Update ticket (no human). 2) **Integrations**: Connect SIEM, EDR, firewall, AD, threat intel feeds via REST APIs. 3) **Case Management**: Track incidents from detection → remediation, SLA tracking. 4) **Threat Intel**: Aggregate feeds (STIX/TAXII), enrich alerts (IP reputation, domain age). Reduces MTTR (Mean Time To Respond) from hours to minutes. Products: Palo Alto XSOAR, Splunk SOAR, IBM Resilient, Swimlane. NOT: Endpoint protection or firewall (orchestrates OTHER tools). Gartner SOAR market guide.'
    },
    {
        id: 'dev52',
        title: 'Threat Intelligence Platform (TIP)',
        points: 8,
        question: 'TIP aggregates threat intel from multiple sources. Which formats/protocols are used? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'stix_taxii', text: 'STIX/TAXII' },
            { value: 'ioc', text: 'IOC (Indicators of Compromise)' },
            { value: 'yara', text: 'YARA rules' },
            { value: 'misp', text: 'MISP feeds' },
            { value: 'jpeg', text: 'JPEG image format' },
            { value: 'mp3', text: 'MP3 audio format' }
        ],
        correct: ['stix_taxii', 'ioc', 'yara', 'misp'],
        explanation: '🔍 Threat Intel Formats: 1) **STIX** (Structured Threat Information Expression) = JSON format for IOCs, TTPs, campaigns. **TAXII** (Trusted Automated Exchange of Indicator Information) = transport protocol. 2) **IOCs**: IP addresses, domains, file hashes, registry keys, YARA rules. 3) **YARA**: Pattern matching for malware families. 4) **MISP** (Malware Information Sharing Platform) = open-source threat sharing. Sources: Commercial (Recorded Future, ThreatConnect), open (AlienVault OTX, CIRCL), ISACs, vendor feeds. TIPs: Anomali, ThreatQ, ThreatConnect. Workflow: Ingest → Normalize → Enrich → Distribute to SIEM/EDR/Firewall. STIX 2.1 standard.'
    },
    {
        id: 'dev53',
        title: 'EDR vs XDR vs MDR',
        points: 8,
        question: 'What is the key difference between EDR, XDR, and MDR?',
        type: 'radio',
        options: [
            { value: 'scope', text: 'EDR=endpoints only, XDR=cross-layer correlation, MDR=managed service' },
            { value: 'cost', text: 'Cost: EDR<XDR<MDR' },
            { value: 'performance', text: 'Performance: MDR is fastest' },
            { value: 'vendor', text: 'Vendor-specific terminology - functionally identical' },
            { value: 'deployment', text: 'On-prem vs cloud deployment models' }
        ],
        correct: 'scope',
        explanation: '🔬 Detection Evolution: **EDR** (Endpoint Detection & Response) = endpoints only (workstations, servers), telemetry: processes, files, registry, network. **XDR** (Extended DR) = correlates endpoint + network + email + cloud, unified console, kill chain visibility. Example: Email attachment → endpoint execution → lateral movement (XDR connects dots). **MDR** (Managed DR) = outsourced SOC, 24/7 monitoring, threat hunting as a service, uses EDR/XDR tools. XDR vendors: Palo Alto Cortex, Microsoft 365 Defender, SentinelOne Singularity. MDR vendors: Arctic Wolf, Expel, Red Canary. XDR = technology, MDR = service. Choose: EDR (have SOC team), XDR (need correlation), MDR (no SOC team).'
    },
    {
        id: 'dev54',
        title: 'NetFlow vs Full Packet Capture',
        points: 7,
        question: 'Organization needs network visibility. NetFlow provides what information compared to full packet capture?',
        type: 'radio',
        options: [
            { value: 'metadata', text: 'Metadata (src/dst IP, ports, bytes, time) but not payload' },
            { value: 'full_packets', text: 'Full packet contents including payload' },
            { value: 'encrypted_only', text: 'Only encrypted traffic' },
            { value: 'dns_only', text: 'Only DNS queries' },
            { value: 'same', text: 'Identical to packet capture' }
        ],
        correct: 'metadata',
        explanation: '📊 NetFlow (Cisco) / sFlow / IPFIX: Flow-based network visibility. Records: src IP, dst IP, src port, dst port, protocol, bytes, packets, timestamps, TCP flags. Does NOT include: Packet payload, HTTP headers, email content. Advantages: 1) Low storage (1000:1 compression vs full capture), 2) Scalable (10Gbps+ links), 3) Long retention (months/years), 4) Privacy-friendly (no payload). Use cases: Baseline traffic, detect beaconing, bandwidth hogs, internal scanning. Full capture: Forensics, malware analysis, compliance (PCAP). Tools: SiLK, nfdump, Zeek. Export: Switch/router → NetFlow collector (ElastiFlow, Plixer). v5 vs v9 vs IPFIX (v10).'
    },
    {
        id: 'dev55',
        title: 'CASB Functionality',
        points: 9,
        question: 'CASB (Cloud Access Security Broker) is deployed between users and cloud apps. What does it provide? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'visibility', text: 'Visibility into shadow IT cloud usage' },
            { value: 'dlp', text: 'DLP for cloud uploads (prevent PII to Dropbox)' },
            { value: 'compliance', text: 'Compliance monitoring (HIPAA, GDPR)' },
            { value: 'threat', text: 'Threat protection (anomalous behavior, compromised accounts)' },
            { value: 'cpu', text: 'CPU performance optimization' },
            { value: 'storage', text: 'Cloud storage provisioning' }
        ],
        correct: ['visibility', 'dlp', 'compliance', 'threat'],
        explanation: '☁️ CASB (Cloud Access Security Broker): Four pillars: 1) **Visibility**: Discover all cloud apps used (shadow IT), track API calls, 2) **Data Security**: DLP policies (block SSN upload to personal OneDrive), encryption, tokenization, 3) **Compliance**: Audit cloud configs, PCI-DSS/HIPAA checks, data residency, 4) **Threat Protection**: Detect compromised accounts (impossible travel), malware in cloud storage, OAuth app risks. Deployment: Inline proxy (forward/reverse) or API-based (out-of-band). Products: Netskope, Zscaler, McAfee MVISION, Microsoft Defender for Cloud Apps. Use case: BYOD accessing corporate SaaS, remote workforce. Not for: CPU/storage management (IaaS concern).'
    },
    {
        id: 'dev56',
        title: 'Deception Technology - Honeypots',
        points: 8,
        question: 'Honeypots deployed on network. What are valid use cases? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'early_warning', text: 'Early warning of internal attacker/malware' },
            { value: 'threat_intel', text: 'Collect attacker TTPs and IOCs' },
            { value: 'distract', text: 'Distract attacker from real assets' },
            { value: 'legal_evidence', text: 'Legal evidence (all honeypot access is unauthorized)' },
            { value: 'production', text: 'Host production applications' },
            { value: 'user_training', text: 'User security awareness training' }
        ],
        correct: ['early_warning', 'threat_intel', 'distract', 'legal_evidence'],
        explanation: '🍯 Honeypot Strategy: Decoy systems with no legitimate purpose. ANY interaction = malicious. 1) **Early Warning**: If honeypot SSH accessed → attacker on network (pivot from real system), alert immediately. 2) **Threat Intel**: Capture malware samples, observe attacker commands, learn TTPs. 3) **Distraction**: Waste attacker time, make environment confusing (100 fake hosts + 10 real). 4) **Attribution**: No false positives (nobody should access), strong evidence for legal action. Types: Low-interaction (emulate services), high-interaction (full OS), honeytokens (fake credentials in files). Products: Canary, TrapX, Illusive. NOT for: Production workloads (security risk), user training (too advanced). Placement: DMZ, internal segments, cloud tenants.'
    },
    {
        id: 'dev57',
        title: 'UEBA - User Behavior Analytics',
        points: 9,
        question: 'UEBA analyzes user behavior to detect insider threats and compromised accounts. Which anomalies does it detect? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'impossible_travel', text: 'Impossible travel (login NYC then London 1 hour later)' },
            { value: 'unusual_access', text: 'Access to unusual resources (HR accessing R&D files)' },
            { value: 'volume', text: 'Unusual data volume (user downloads 10GB normally 10MB)' },
            { value: 'time', text: 'Access at unusual times (2AM login from office worker)' },
            { value: 'slow_typing', text: 'Slow typing speed' },
            { value: 'font_size', text: 'Unusual font size in emails' }
        ],
        correct: ['impossible_travel', 'unusual_access', 'volume', 'time'],
        explanation: '👤 UEBA (User and Entity Behavior Analytics): Machine learning baselines normal behavior. Detects: 1) **Impossible Travel**: Tokyo login 10:00 AM, London login 10:30 AM (can\'t fly that fast = compromised credentials). 2) **Lateral Movement**: Finance user accessing Engineering file shares (abnormal peer group). 3) **Data Exfiltration**: User downloads 50GB (normal = 5GB/month). 4) **Off-hours Access**: 3 AM weekend login from sales rep (normal = M-F 9-5). 5) **Failed Login Spikes**: 50 failed then success (brute force). Also: New device/location, privilege escalation, USB usage. Products: Exabeam, Securonix, Splunk UBA. Standalone or SIEM-integrated. Reduces investigation time, finds insider threats signature-based tools miss.'
    },
    {
        id: 'dev58',
        title: 'Zero Trust Network Access (ZTNA)',
        points: 8,
        question: 'ZTNA replaces traditional VPN. What principle does it follow?',
        type: 'radio',
        options: [
            { value: 'never_trust', text: 'Never trust, always verify - verify every access request' },
            { value: 'trust_network', text: 'Trust internal network, verify external only' },
            { value: 'trust_users', text: 'Trust authenticated users completely' },
            { value: 'faster_vpn', text: 'Same as VPN but faster' },
            { value: 'no_authentication', text: 'No authentication required' }
        ],
        correct: 'never_trust',
        explanation: '🔒 Zero Trust: "Never trust, always verify." Traditional VPN = authenticate once → access entire network (flat network). ZTNA = 1) Verify identity (MFA), 2) Verify device (posture check: OS patched? EDR installed?), 3) Verify context (location, time, risk score), 4) Grant least-privilege access to SPECIFIC app (not network), 5) Continuous verification (re-auth every hour). No network access = can\'t pivot laterally. Components: Identity provider (Okta, Azure AD), policy engine, broker. Products: Zscaler Private Access, Palo Alto Prisma Access, Cloudflare Access. Protocols: SDP (Software Defined Perimeter), BeyondCorp (Google). Use case: Remote workforce, third-party access. Gartner: ZTNA replacing VPN by 2025.'
    },
    {
        id: 'dev59',
        title: 'IDS Evasion Techniques',
        points: 8,
        question: 'Attackers use which techniques to evade IDS/IPS signatures? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'fragmentation', text: 'Packet fragmentation to split attack across packets' },
            { value: 'encoding', text: 'URL encoding or obfuscation (char codes)' },
            { value: 'polymorphism', text: 'Polymorphic shellcode' },
            { value: 'encryption', text: 'Encrypted payloads (HTTPS without inspection)' },
            { value: 'slow_scan', text: 'Slow scanning to avoid rate limits' },
            { value: 'loud_noise', text: 'Generate loud noise' }
        ],
        correct: ['fragmentation', 'encoding', 'polymorphism', 'encryption', 'slow_scan'],
        explanation: '🎭 IDS Evasion: Signature-based detection can be bypassed. 1) **Fragmentation**: Split malicious payload across multiple packets/fragments, IDS inspects each individually (doesn\'t see full attack). Defense: Stream reassembly. 2) **Encoding**: %2e%2e%2f%2e%2e%2f (../..) bypasses "../" signature. Unicode, double encoding, hex encoding. Defense: Normalize before inspection. 3) **Polymorphism**: Shellcode changes signature each time (encrypted + different decryption stub). Defense: Behavioral/heuristic. 4) **Encryption**: HTTPS/TLS hides payload. Defense: SSL inspection. 5) **Timing**: Slow scan (1 port/hour) vs threshold (100 ports/min). Defense: Long-term state tracking. Tools: Fragroute, ADMmutate. IDS tuning critical.'
    },
    {
        id: 'dev60',
        title: 'NAC - Network Access Control',
        points: 7,
        question: 'NAC enforces policy before allowing device onto network. What does it check? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'posture', text: 'Device posture (OS patches, antivirus status)' },
            { value: 'identity', text: 'User/device identity (802.1X authentication)' },
            { value: 'compliance', text: 'Corporate compliance (encryption enabled, host firewall on)' },
            { value: 'role', text: 'Role-based access (employee vs contractor vs guest)' },
            { value: 'cpu_speed', text: 'CPU processing speed' },
            { value: 'screen_size', text: 'Monitor screen resolution' }
        ],
        correct: ['posture', 'identity', 'compliance', 'role'],
        explanation: '🚪 NAC (Network Access Control): Pre-admission checks before network access. 1) **Identity**: Who? (802.1X with RADIUS, certificate-based auth, MAC authentication). 2) **Posture**: Is device healthy? (Windows patches current? AV definitions updated? Host firewall enabled? Disk encrypted?). 3) **Compliance**: Corporate policy (MDM enrolled, jailbroken?). 4) **Role**: Employee (full access), contractor (limited), guest (internet only), quarantine VLAN for non-compliant. Post-admission: Continuous monitoring, revoke if posture changes. Products: Cisco ISE, Aruba ClearPass, FortiNAC, PacketFence. Protocols: 802.1X (port-based), MAC authentication (bypass for IoT), web portal (guest). BYOD = major NAC use case.'
    },
    {
        id: 'dev61',
        title: 'Web Proxy vs Reverse Proxy',
        points: 7,
        question: 'What is the key difference between forward proxy and reverse proxy?',
        type: 'radio',
        options: [
            { value: 'direction', text: 'Forward proxy serves clients (outbound), reverse proxy serves servers (inbound)' },
            { value: 'speed', text: 'Reverse proxy is faster' },
            { value: 'security', text: 'Forward proxy is more secure' },
            { value: 'protocol', text: 'Different protocols (HTTP vs HTTPS)' },
            { value: 'identical', text: 'No difference - same technology' }
        ],
        correct: 'direction',
        explanation: '🔄 Proxy Types: **Forward Proxy** (explicit proxy): Client → Proxy → Internet. Use cases: 1) Content filtering (block porn, social media), 2) Caching (speed up), 3) Anonymity (hide client IP), 4) DLP (inspect outbound). Client configured to use proxy (browser settings, PAC file, WPAD). Products: Squid, Blue Coat (Symantec), Zscaler. **Reverse Proxy**: Internet → Proxy → Internal servers. Use cases: 1) Load balancing, 2) SSL offloading, 3) Web application firewall, 4) Caching (CDN), 5) Hide internal topology. Client unaware (DNS points to proxy). Products: NGINX, HAProxy, F5. Transparent proxy = intercepts traffic without client config (WCCP, PBR).'
    },
    {
        id: 'dev62',
        title: 'Vulnerability Scanner Types',
        points: 8,
        question: 'Authenticated vs unauthenticated vulnerability scans. What is the difference?',
        type: 'radio',
        options: [
            { value: 'credentials', text: 'Authenticated uses credentials to log into systems, finds more vulns' },
            { value: 'speed', text: 'Authenticated scans are faster' },
            { value: 'network', text: 'Authenticated is network-based, unauthenticated is agent-based' },
            { value: 'compliance', text: 'Authenticated is for compliance only' },
            { value: 'no_difference', text: 'No difference in vulnerability detection' }
        ],
        correct: 'credentials',
        explanation: '🔍 Scan Types: **Unauthenticated** (network scan): Scanner probes from network, sees what attacker sees, finds externally-exploitable vulns, limited visibility (can\'t see local privesc, missing patches, config issues). **Authenticated** (credentialed scan): Scanner logs into system (SSH, WMI), queries installed patches, reads configs, checks file permissions, registry, finds 10x more issues. Example: Unauth sees "port 22 open", Auth sees "SSH weak ciphers, root login enabled, OpenSSH 7.4 (CVE-2018-15473)". Best practice: Both types. Unauth = attacker view, Auth = comprehensive. Tools: Nessus, Qualys, Rapid7. Credentials: Local admin (Windows), root/sudo (Linux), read-only sufficient. PCI-DSS requires quarterly scans. Scan frequency: Monthly internal, quarterly external.'
    },
    {
        id: 'dev63',
        title: 'SIEM Data Models',
        points: 8,
        question: 'SIEM data models normalize diverse log formats. What is the purpose?',
        type: 'radio',
        options: [
            { value: 'common_schema', text: 'Map diverse formats to common schema for correlation' },
            { value: 'compression', text: 'Compress logs to save storage' },
            { value: 'encryption', text: 'Encrypt sensitive log data' },
            { value: 'faster_search', text: 'Speed up search queries only' },
            { value: 'visualization', text: 'Create dashboards only' }
        ],
        correct: 'common_schema',
        explanation: '📐 Data Normalization: Different log formats = correlation nightmare. Firewall: "src_ip", Windows: "Source_Address", Syslog: "SrcIP". Data model maps to common schema: src_ip, dst_ip, user, action, timestamp. Enables: 1) **Correlation**: "Failed login from src_ip then RDP from same src_ip" rule works across all log sources. 2) **Dashboards**: Single "Top Sources" table shows firewall + proxy + VPN. 3) **Search**: "search src_ip=1.2.3.4" queries all sources. Common models: **CIM** (Splunk Common Information Model), **ECS** (Elastic Common Schema), **Sigma** (detection rules). Custom parsing: Regex, Grok patterns, field extractors. Normalization = slower ingestion but essential for analytics. Without: Write separate rules for each log source (unmaintainable).'
    },
    {
        id: 'dev64',
        title: 'SSL/TLS Inspection - Decryption Points',
        points: 8,
        question: 'Where can SSL/TLS decryption be performed? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'proxy', text: 'Forward proxy (outbound HTTPS)' },
            { value: 'ngfw', text: 'NGFW inline' },
            { value: 'load_balancer', text: 'Load balancer (inbound HTTPS to servers)' },
            { value: 'endpoint', text: 'Endpoint agent' },
            { value: 'router', text: 'Layer 3 router' },
            { value: 'switch', text: 'Layer 2 switch' }
        ],
        correct: ['proxy', 'ngfw', 'load_balancer', 'endpoint'],
        explanation: '🔓 SSL Inspection Points: **Outbound (user → internet)**: 1) **Proxy** (explicit/transparent): Intercepts client HTTPS, presents proxy cert, decrypts, inspects, re-encrypts to server. 2) **NGFW**: Inline SSL inspection. **Inbound (internet → servers)**: 3) **Load Balancer**: SSL offloading, decrypt HTTPS, forward HTTP to servers (servers see plaintext), inspected by IDS/WAF. 4) **Endpoint**: Agent (Symantec, Cisco AMP) inspects before encryption. Routers/switches = Layer 2/3 only (no SSL state). Challenges: Cert trust (install root CA on all devices), pinning breaks apps, privacy concerns, CPU intensive. Don\'t decrypt: Banking, healthcare (whitelist). Dual: Decrypt by default, whitelist exceptions.'
    },
    {
        id: 'dev65',
        title: 'Security Data Lake vs SIEM',
        points: 8,
        question: 'Organization builds security data lake. How does it differ from traditional SIEM?',
        type: 'radio',
        options: [
            { value: 'scale_cost', text: 'Data lake: cheaper storage, scales to petabytes, flexible schema' },
            { value: 'faster', text: 'Data lake provides faster searches' },
            { value: 'better_correlation', text: 'Data lake has better correlation engine' },
            { value: 'easier_deploy', text: 'Data lake is easier to deploy' },
            { value: 'identical', text: 'No difference - marketing terms' }
        ],
        correct: 'scale_cost',
        explanation: '🏞️ Data Lake Evolution: **Traditional SIEM**: Proprietary storage, indexed search, correlation engine, expensive ($$$$/GB/day), limited retention (90 days), schema-on-write. **Data Lake**: Object storage (S3, ADLS), store raw logs forever, schema-on-read, 10x cheaper, use cases: 1) Long-term forensics (store 2 years), 2) Threat hunting (query historical data), 3) Compliance (GDPR, HIPAA = multi-year retention), 4) ML training data. Architecture: Logs → Data lake (cheap bulk storage) + SIEM (hot data, 30 days for real-time alerts). Query: Athena (AWS), Log Analytics (Azure), Splunk Data Fabric. Trade-off: Data lake = slow queries, SIEM = fast but expensive. Modern: Hybrid approach, SIEM + data lake backend.'
    },
    {
        id: 'dev66',
        title: 'IPS Tuning - False Positives',
        points: 7,
        question: 'IPS blocks legitimate traffic (false positive). What is the correct tuning approach?',
        type: 'radio',
        options: [
            { value: 'tune_rule', text: 'Tune signature: whitelist source/dest, adjust threshold, or disable' },
            { value: 'disable_ips', text: 'Disable IPS entirely' },
            { value: 'detection_mode', text: 'Switch to detection-only mode permanently' },
            { value: 'ignore', text: 'Ignore - security over availability' },
            { value: 'increase_bandwidth', text: 'Increase bandwidth allocation' }
        ],
        correct: 'tune_rule',
        explanation: '🎯 IPS Tuning: False positives = business disruption. Root cause: Overly broad signature, legitimate protocol behavior, version-specific behavior. Tuning options: 1) **Whitelist**: Allow specific src/dst IP pair, 2) **Threshold**: Trigger after 10 events not 1, 3) **Disable signature**: If signature outdated/incorrect (document why), 4) **Custom signature**: Write more specific rule, 5) **Exception**: Allow for specific application. Process: Alert → Investigate (truly false?) → Tune → Test → Document. DON\'T: Disable IPS (defeats purpose), ignore (users suffer). Tuning workflow: Detection mode → Baseline (1-2 weeks) → Tune false positives → Enable blocking → Monitor → Re-tune. Signature updates = new false positives (regression test). Annual review: Remove outdated exceptions.'
    },
    {
        id: 'dev67',
        title: 'PKI Infrastructure',
        points: 8,
        question: 'Internal PKI for enterprise. Which components are required? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'ca', text: 'Certificate Authority (CA)' },
            { value: 'crl', text: 'Certificate Revocation List (CRL) or OCSP' },
            { value: 'ra', text: 'Registration Authority (RA) for cert requests' },
            { value: 'root_trust', text: 'Root CA certificate distributed to all devices' },
            { value: 'backup_power', text: 'UPS backup power' },
            { value: 'quantum_computer', text: 'Quantum computer for encryption' }
        ],
        correct: ['ca', 'crl', 'ra', 'root_trust'],
        explanation: '🔐 PKI (Public Key Infrastructure): Components: 1) **Root CA**: Signs subordinate CAs, kept offline (air-gapped), generates for 10-20 years. 2) **Subordinate/Issuing CA**: Issues end-entity certs (servers, users, devices), online, shorter lifetime. 3) **RA** (Registration Authority): Validates requests before CA signs (identity verification). 4) **CRL/OCSP**: Revocation checking (cert compromised = add to CRL). 5) **Root Trust**: Deploy root CA cert to all endpoints (GPO, MDM). Use cases: Internal HTTPS, code signing, email encryption (S/MIME), VPN, 802.1X, document signing. Tools: Microsoft ADCS, OpenSSL, HashiCorp Vault. Hierarchy: Root → Intermediate → Issuing CA (security in depth). Certificate templates, auto-enrollment, validity periods (1 year server certs). Compromise = re-issue ALL certs.'
    },
    {
        id: 'dev68',
        title: 'Cloud Security Posture Management (CSPM)',
        points: 8,
        question: 'CSPM tools monitor cloud infrastructure. What do they detect? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'misconfiguration', text: 'Misconfigurations (S3 bucket public, security group 0.0.0.0/0)' },
            { value: 'compliance', text: 'Compliance violations (CIS benchmarks, PCI-DSS)' },
            { value: 'iam', text: 'Excessive IAM permissions (privilege creep)' },
            { value: 'cost', text: 'Cost optimization opportunities (unused resources)' },
            { value: 'on_prem', text: 'On-premises server misconfigurations' },
            { value: 'physical_security', text: 'Physical datacenter security' }
        ],
        correct: ['misconfiguration', 'compliance', 'iam', 'cost'],
        explanation: '☁️ CSPM (Cloud Security Posture Management): Continuous monitoring of IaaS/PaaS configs. Detects: 1) **Misconfigurations**: S3 public read, RDS without encryption, NSG allows SSH from internet, root account usage, MFA disabled. 2) **Compliance**: CIS AWS Foundations, NIST, HIPAA, PCI-DSS benchmarks, drift from baselines. 3) **IAM**: Over-privileged roles (admin everywhere), unused credentials (90 days), cross-account risks. 4) **Network Exposure**: Public IPs, VPC peering risks, exposed databases. Also: Cost optimization (unused EBS, old snapshots). Products: Prisma Cloud (Palo Alto), Wiz, Orca, AWS Security Hub. API-based (read-only), agent-less. Remediation: Manual, auto-remediation (Lambda), infrastructure-as-code integration (Terraform). Multi-cloud support (AWS, Azure, GCP). NOT for: On-prem, physical security.'
    },
    {
        id: 'dev69',
        title: 'Security Analytics - ML/AI',
        points: 8,
        question: 'Machine learning in security tools. Which techniques are commonly used? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'anomaly', text: 'Anomaly detection (baseline normal, flag deviations)' },
            { value: 'clustering', text: 'Clustering (group similar entities/behaviors)' },
            { value: 'classification', text: 'Classification (malware vs benign)' },
            { value: 'nlp', text: 'NLP for threat intel extraction' },
            { value: 'time_travel', text: 'Time travel prediction' },
            { value: 'mind_reading', text: 'Attacker intent reading' }
        ],
        correct: ['anomaly', 'clustering', 'classification', 'nlp'],
        explanation: '🤖 Security ML: 1) **Anomaly Detection** (unsupervised): Baseline normal behavior (user logs in 9-5 from NYC), alert on deviation (3 AM from Russia). UEBA use case. 2) **Clustering** (unsupervised): Group similar malware samples, host behaviors, network flows. Discovers new attack patterns. 3) **Classification** (supervised): Train on labeled data (malware/benign), predict unknown files. AV/EDR use case. Decision trees, random forest, neural nets. 4) **NLP**: Extract IOCs from unstructured threat reports, auto-tag incidents. Use cases: Phishing detection (email analysis), DGA detection (domain names), SIEM alert prioritization. Challenges: Adversarial ML (attackers game algorithms), false positives, model drift (retrain quarterly). Tools: Darktrace, Vectra, Cylance (now ML-based AV). Explainability critical (understand why model flagged).'
    },
    {
        id: 'dev70',
        title: 'Threat Hunting Platform',
        points: 9,
        question: 'Proactive threat hunting requires which data sources? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'edr_telemetry', text: 'EDR telemetry (process execution, network, file activity)' },
            { value: 'netflow', text: 'Network flow data (NetFlow, Zeek logs)' },
            { value: 'dns', text: 'DNS query logs' },
            { value: 'threat_intel', text: 'Threat intelligence feeds' },
            { value: 'siem', text: 'SIEM historical data' },
            { value: 'social_media', text: 'Employee social media posts' }
        ],
        correct: ['edr_telemetry', 'netflow', 'dns', 'threat_intel', 'siem'],
        explanation: '🎯 Threat Hunting: Proactive search for threats bypassing automated detection. Data sources: 1) **EDR**: Process lineage, loaded DLLs, registry mods, memory, PowerShell commands. Hunt: "powershell.exe with -enc" (obfuscation). 2) **NetFlow**: Beaconing detection (regular intervals), long connections, data exfil (high upload). 3) **DNS**: DGA domains (high entropy), tunneling (long queries), newly registered domains. 4) **Threat Intel**: IOCs (hunt for known-bad IPs/domains in historical data), YARA rules. 5) **SIEM**: Correlate across sources, historical baselines. Hunting hypotheses: "APT29 uses specific LOLBins - search cmd.exe launching certutil", "Ransomware renames files - find mass .locked extension". Tools: HELK, Jupyter notebooks, Splunk, Elastic. Cadence: Weekly hunts, document findings. MITRE ATT&CK-based hunting. Success metric: Threats found before incident.'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = devicesExtended;
}
