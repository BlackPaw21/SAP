/**
 * Extended Firewall Questions (fw51-70)
 * Lazy-loaded when user clicks "Load More Questions"
 */

const firewallExtended = [
    {
        id: 'fw51',
        title: 'Zone-Based Firewall Policy',
        points: 9,
        question: 'Zone-based firewall has zones: TRUST, DMZ, UNTRUST. Default inter-zone policy is DENY. Which policy is MOST secure for DMZ web server?',
        type: 'radio',
        options: [
            { value: 'untrust_dmz_dmz_trust', text: 'UNTRUST→DMZ:80,443 ALLOW | DMZ→TRUST:3306 ALLOW | All others DENY' },
            { value: 'any_any', text: 'ANY→ANY ALLOW with IPS inspection' },
            { value: 'trust_dmz', text: 'TRUST→DMZ ALLOW | DMZ→TRUST DENY' },
            { value: 'dmz_full', text: 'DMZ→UNTRUST ALLOW | UNTRUST→DMZ ALLOW' },
            { value: 'implicit_only', text: 'Rely on implicit deny only' }
        ],
        correct: 'untrust_dmz_dmz_trust',
        explanation: '🌐 Zone-Based Firewall: Zones group interfaces by trust level. Inter-zone traffic requires explicit policy. Best practice: UNTRUST(Internet)→DMZ allows only web ports (80/443), DMZ→TRUST allows only specific database (3306 to specific IP), DMZ→UNTRUST DENY (no outbound unless needed for updates). Prevents: Compromised DMZ server pivoting to internal network, data exfiltration. Cisco ZBF, Palo Alto Security Zones, Fortinet Virtual Domains. Zero Trust principle: No implicit trust between zones. Tools: Zone protection profiles, APP-ID filtering per zone.'
    },
    {
        id: 'fw52',
        title: 'Hairpin NAT (NAT Reflection)',
        points: 8,
        question: 'Internal user 10.1.1.50 accesses company website via public IP 203.0.113.10 (NAT\'d to internal 10.1.1.100). Without hairpin NAT, what happens?',
        type: 'radio',
        options: [
            { value: 'connection_fails', text: 'Connection fails - return traffic routing issue' },
            { value: 'works_fine', text: 'Works normally' },
            { value: 'slow', text: 'Works but with high latency' },
            { value: 'dns_error', text: 'DNS resolution fails' },
            { value: 'loop', text: 'Routing loop occurs' }
        ],
        correct: 'connection_fails',
        explanation: '🔄 Hairpin NAT Problem: Client 10.1.1.50 sends packet to 203.0.113.10, firewall NATs to 10.1.1.100, server replies with src=10.1.1.100 dst=10.1.1.50 (NOT 203.0.113.10), client rejects (expects reply from 203.0.113.10). Hairpin/NAT Reflection solution: Firewall re-NATs return traffic src=203.0.113.10. Alternative: Split-horizon DNS (internal DNS returns 10.1.1.100, external returns 203.0.113.10). Common issue: SaaS apps, VPN users, cloud migrations. Cisco ASA: "same-security-traffic permit intra-interface". Performance impact: Double NAT processing.'
    },
    {
        id: 'fw53',
        title: 'IPv6 Firewall Challenges',
        points: 9,
        question: 'Deploying IPv6 alongside IPv4. What IPv6-specific firewall considerations exist? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'icmpv6_required', text: 'ICMPv6 required for Neighbor Discovery (cannot block all)' },
            { value: 'extension_headers', text: 'IPv6 extension headers can hide attacks' },
            { value: 'auto_config', text: 'SLAAC auto-configuration can bypass controls' },
            { value: 'tunneling', text: 'IPv6 tunneling (6to4, Teredo) can bypass firewall' },
            { value: 'identical', text: 'IPv6 rules identical to IPv4' },
            { value: 'no_nat', text: 'No NAT in IPv6 simplifies firewall design' }
        ],
        correct: ['icmpv6_required', 'extension_headers', 'auto_config', 'tunneling'],
        explanation: '🌐 IPv6 Firewall Security: 1) ICMPv6 Types 133-137 (ND) MUST be allowed (unlike IPv4 ICMP), 2) Extension headers (fragment, routing, hop-by-hop) can evade inspection - block or deep inspect, 3) SLAAC auto-assigns IPs bypassing DHCP controls - use DHCPv6, disable SLAAC, 4) Tunnels (6to4, Teredo, ISATAP) encapsulate IPv6 in IPv4 bypassing IPv4-only rules. Defense: Dual-stack firewall rules, disable IPv6 if not used, tunnel broker blocking. Common mistake: IPv4 firewall only while IPv6 wide open. RFC 6092 (IPv6 firewall recommendations).'
    },
    {
        id: 'fw54',
        title: 'SSL/TLS Inspection Risks',
        points: 8,
        question: 'Organization implements SSL inspection (break-and-inspect). What are valid security concerns? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'cert_pinning', text: 'Breaks certificate pinning in mobile apps' },
            { value: 'privacy', text: 'Inspects encrypted medical/financial data' },
            { value: 'weak_crypto', text: 'May downgrade to weaker ciphers' },
            { value: 'trust', text: 'Requires trusting firewall CA on all devices' },
            { value: 'perfect_security', text: 'Provides perfect security with no downsides' },
            { value: 'cpu_intensive', text: 'CPU-intensive operation' }
        ],
        correct: ['cert_pinning', 'privacy', 'weak_crypto', 'trust', 'cpu_intensive'],
        explanation: '🔐 SSL Inspection Tradeoffs: Firewall acts as man-in-the-middle (MITM). Benefits: Detect malware in HTTPS, prevent data exfiltration, enforce DLP. Risks: 1) Cert pinning breaks (mobile apps, APIs crash), 2) Privacy concerns (decrypt banking, healthcare - compliance issues), 3) Cipher downgrade (firewall supports TLS 1.1, client/server use 1.3), 4) CA private key on firewall = single point of compromise, 5) CPU/latency impact. Best practice: Decrypt selectively (whitelist banking/health), use dedicated decryption appliance, HSM for keys, monitor for failures. Legal compliance: HIPAA, GDPR, PCI-DSS considerations.'
    },
    {
        id: 'fw55',
        title: 'Application Layer Gateway (ALG)',
        points: 7,
        question: 'SIP VoIP calls fail through firewall. Disabling SIP ALG fixes the issue. What was the ALG doing?',
        type: 'radio',
        options: [
            { value: 'alg_breaks', text: 'ALG modifying SIP packets incorrectly, corrupting protocol' },
            { value: 'blocking', text: 'Blocking all SIP traffic' },
            { value: 'encrypting', text: 'Encrypting SIP packets' },
            { value: 'routing', text: 'Routing SIP to wrong destination' },
            { value: 'logging', text: 'Only logging SIP traffic' }
        ],
        correct: 'alg_breaks',
        explanation: '🔧 ALG (Application Layer Gateway): Inspects/modifies application payload for protocols with dynamic ports/embedded IPs. SIP ALG rewrites IP addresses in SIP headers (SDP session description), opens dynamic RTP ports. Problem: ALGs often buggy, conflict with NAT traversal (STUN/TURN), break encryption. Also affects: FTP (PORT/PASV commands), H.323, PPTP, TFTP. Symptoms: One-way audio, connection hangs, NAT issues. Solution: Disable ALG, use application-native NAT traversal, configure static port ranges. Cisco ASA: "no fixup protocol sip". Modern apps designed for NAT (STUN), don\'t need ALG.'
    },
    {
        id: 'fw56',
        title: 'Asymmetric Routing',
        points: 9,
        question: 'Outbound traffic flows through Firewall-A, return traffic through Firewall-B (different ISP). Stateful firewall drops return traffic. Why?',
        type: 'radio',
        options: [
            { value: 'no_session', text: 'Firewall-B has no session state for return traffic' },
            { value: 'wrong_rule', text: 'Wrong firewall rule configuration' },
            { value: 'routing_loop', text: 'Routing loop detected' },
            { value: 'ttl_expired', text: 'TTL expired on return path' },
            { value: 'nat_issue', text: 'NAT translation only' }
        ],
        correct: 'no_session',
        explanation: '⚠️ Asymmetric Routing: Stateful firewall expects to see both SYN and SYN-ACK. Firewall-A sees outbound SYN (creates session), Firewall-B sees return SYN-ACK (no session = invalid state = DROP). Common in: Multi-ISP, load balancers, ECMP routing, cloud hybrid. Solutions: 1) Symmetric routing (policy-based routing, BGP manipulation), 2) Session synchronization between firewalls (HA cluster), 3) Disable stateful inspection (use stateless ACLs - less secure), 4) Single firewall in traffic path. Detection: tcpdump on both firewalls, asymmetric flow counters. Palo Alto: "asymmetric-path" setting.'
    },
    {
        id: 'fw57',
        title: 'Fragment Handling',
        points: 8,
        question: 'Firewall rule: ALLOW dst_port=80. Attacker sends fragmented packets where TCP header is in 2nd fragment. What happens?',
        type: 'radio',
        options: [
            { value: 'bypass_or_drop', text: 'May bypass or be dropped depending on firewall fragment handling' },
            { value: 'always_allow', text: 'Always allowed' },
            { value: 'always_block', text: 'Always blocked' },
            { value: 'reassemble', text: 'Firewall always reassembles correctly' },
            { value: 'forward_to_ids', text: 'Forwarded to IDS only' }
        ],
        correct: 'bypass_or_drop',
        explanation: '🧩 Fragment Attacks: IP fragmentation splits packets into pieces. 1st fragment has IP+TCP headers, subsequent fragments only IP header. Stateless firewall checking dst_port can\'t inspect 2nd fragment (no TCP header) → may allow blindly (bypass) or drop all fragments (DoS). Modern stateful firewalls: Virtual reassembly before inspection. Attacks: Tiny fragments, overlapping fragments, timeout exhaustion. Defense: Enable fragment reassembly, set minimum fragment size (drop tiny frags), fragment timeout tuning, drop fragmented packets from untrusted sources. IPv6: Fragmentation only at source (not routers). Tools: fragroute, Scapy. CWE-404.'
    },
    {
        id: 'fw58',
        title: 'Connection Table Exhaustion',
        points: 8,
        question: 'Firewall connection table capacity: 100,000 sessions. Attack generates 200,000 half-open connections. What happens?',
        type: 'radio',
        options: [
            { value: 'table_full_dos', text: 'Connection table fills, legitimate traffic denied (DoS)' },
            { value: 'oldest_removed', text: 'Oldest connections automatically removed' },
            { value: 'unlimited', text: 'Firewall dynamically expands table' },
            { value: 'attacker_blocked', text: 'Attacker IPs automatically blocked' },
            { value: 'performance_ok', text: 'Performance degrades but no denial' }
        ],
        correct: 'table_full_dos',
        explanation: '💥 Resource Exhaustion DoS: Firewall connection table = finite memory. SYN flood creates half-open connections (SYN received, SYN-ACK sent, no ACK). Each consumes table entry. At capacity: Firewall drops NEW connections (legitimate users denied). Defense: 1) SYN cookies (stateless SYN-ACK), 2) Aggressive timeouts for half-open (30s instead of 60s), 3) Connection limits per source IP, 4) Rate limiting SYN packets, 5) DDoS mitigation (Cloudflare, AWS Shield). Monitor: Connection table utilization (alert >80%). Capacity planning: Size table for peak + 50% headroom. Also: UDP flood, ICMP flood exhaust resources.'
    },
    {
        id: 'fw59',
        title: 'Time-Based Access Control',
        points: 7,
        question: 'Rule allows SSH access only Monday-Friday 9AM-5PM EST. User in Tokyo (JST, +13h ahead) tries to connect Tuesday 3PM JST. Is access allowed?',
        type: 'radio',
        options: [
            { value: 'check_timezone', text: 'Depends on firewall timezone configuration' },
            { value: 'always_allow', text: 'Always allowed (during business hours somewhere)' },
            { value: 'always_deny', text: 'Always denied' },
            { value: 'user_timezone', text: 'Based on user\'s local timezone' },
            { value: 'geo_lookup', text: 'Firewall does GeoIP timezone lookup' }
        ],
        correct: 'check_timezone',
        explanation: '🕐 Time-Based ACLs: Firewall uses its own clock/timezone. Tokyo 3PM JST = 2AM EST (Tuesday) → DENIED (outside 9AM-5PM EST window). Configuration: Set firewall to UTC (universal), specify rules in UTC, or clearly document timezone. Use cases: After-hours block high-risk access (RDP, admin), maintenance windows, compliance (restrict trading hours). Challenges: Daylight saving time transitions, multi-timezone orgs, clock skew. Tools: NTP synchronization critical (drift = incorrect enforcement). Logging shows firewall timestamp. Test rules during DST transitions. Palo Alto: schedule objects, Cisco ASA: time-range.'
    },
    {
        id: 'fw60',
        title: 'Cloud Security Groups vs NACLs',
        points: 9,
        question: 'AWS VPC has both Security Groups and Network ACLs. What is the key difference?',
        type: 'radio',
        options: [
            { value: 'stateful_vs_stateless', text: 'Security Groups are stateful, NACLs are stateless' },
            { value: 'sg_faster', text: 'Security Groups process faster' },
            { value: 'nacl_encrypted', text: 'NACLs provide encryption' },
            { value: 'identical', text: 'Functionally identical' },
            { value: 'sg_subnet', text: 'Security Groups apply to subnets, NACLs to instances' }
        ],
        correct: 'stateful_vs_stateless',
        explanation: '☁️ AWS Firewall Layers: Security Groups (SG) = stateful, instance-level, allow-only (implicit deny), applies to ENI. Network ACLs (NACL) = stateless, subnet-level, allow+deny rules, numbered priority. Example: SG allows outbound 443, return traffic auto-allowed. NACL needs explicit inbound rule for ephemeral ports (1024-65535). Defense in depth: NACL = subnet boundary protection (block IPs), SG = instance micro-segmentation (app-specific). Common mistake: NACL blocks return traffic (forgot ephemeral ports). Best practice: Default DENY NACL, specific SGs per app tier. Azure equivalent: NSG (stateful). GCP: VPC Firewall (stateful, tag-based).'
    },
    {
        id: 'fw61',
        title: 'Rule Shadowing Detection',
        points: 8,
        question: 'Rule 10: ALLOW src=10.0.0.0/8 dst=any port=any. Rule 50: DENY src=10.1.1.0/24 dst=192.168.1.100 port=22. What is the issue?',
        type: 'radio',
        options: [
            { value: 'shadowed', text: 'Rule 50 is shadowed (never executes) - Rule 10 matches first' },
            { value: 'correct', text: 'Rules configured correctly' },
            { value: 'conflict', text: 'Rules conflict - firewall error' },
            { value: 'rule10_shadowed', text: 'Rule 10 is shadowed' },
            { value: 'performance', text: 'Performance issue only' }
        ],
        correct: 'shadowed',
        explanation: '👻 Rule Shadowing: First-match wins in top-down processing. 10.1.1.0/24 is subset of 10.0.0.0/8. Traffic from 10.1.1.50 to 192.168.1.100:22 → matches Rule 10 (ALLOW) → never reaches Rule 50 (DENY). Rule 50 = dead code. Detection: Firewall analyzers (AlgoSec, Tufin, Firemon), manual rule review, hit counters (0 hits = potential shadow). Fix: Reorder (specific before general), remove redundant rules. Also check: Generalization (broader rule after specific), correlation (multiple rules same traffic), redundancy (duplicate rules). Annual rule audit critical. Tools: fwanalyzer, Nipper, vendor tools (Palo Alto BPA).'
    },
    {
        id: 'fw62',
        title: 'Double NAT Scenario',
        points: 9,
        question: 'User behind home NAT (192.168.1.0/24) connects to corporate VPN. Corporate also uses 192.168.1.0/24. What issue occurs?',
        type: 'radio',
        options: [
            { value: 'ip_conflict', text: 'IP address overlap causes routing conflicts' },
            { value: 'works_fine', text: 'VPN encryption prevents any issues' },
            { value: 'dns_only', text: 'DNS resolution problems only' },
            { value: 'slow_connection', text: 'Slow performance only' },
            { value: 'automatic_fix', text: 'VPN automatically renumbers' }
        ],
        correct: 'ip_conflict',
        explanation: '🔀 Double NAT + IP Overlap: User has 192.168.1.50, VPN assigns 192.168.1.100. Routing table: "192.168.1.0/24 → local" conflicts with "192.168.1.0/24 → VPN tunnel". Traffic to corporate 192.168.1.X goes to home network instead. Solutions: 1) NAT-T (NAT Traversal) - additional NAT layer, 2) Unique corporate IP space (10.x.x.x), 3) VPN client detects overlap, auto-renumbers, 4) Split-tunnel VPN (only corp traffic through VPN). Prevention: Use non-RFC1918 overlapping space, unique subnets. Common in: Home workers, customer networks, acquisitions. Test: traceroute, verify routing table. Tools: VPN diagnostics, route print/netstat -r.'
    },
    {
        id: 'fw63',
        title: 'Firewall Change Management',
        points: 7,
        question: 'Best practice for emergency firewall rule change at 2AM during active incident?',
        type: 'radio',
        options: [
            { value: 'document_after', text: 'Implement immediately, document afterward, schedule review' },
            { value: 'wait_approval', text: 'Wait for change advisory board approval' },
            { value: 'no_change', text: 'Never change firewall during incident' },
            { value: 'reboot_required', text: 'Always reboot firewall after changes' },
            { value: 'disable_logging', text: 'Disable logging before changes' }
        ],
        correct: 'document_after',
        explanation: '🚨 Emergency Change: Incident response prioritizes containment over process. Implement rule (block attacker IP, isolate compromised host), document in ticket, notify team, schedule post-incident review. Standard change: CAB approval, peer review, testing, maintenance window. Emergency: Senior approval, implement, document. Best practices: 1) Emergency policy defined (who authorizes), 2) Audit trail (who, what, when, why), 3) Review within 24h (remove temporary rules), 4) Runbook for common scenarios, 5) Rollback plan. Tools: Change tracking (FireMon, AlgoSec), version control (Git for configs), backup before change. NEVER reboot production firewall without reason.'
    },
    {
        id: 'fw64',
        title: 'Service Objects vs Port Numbers',
        points: 6,
        question: 'Why use service objects (e.g., "HTTPS") instead of port numbers (443/TCP) in firewall rules?',
        type: 'checkbox',
        options: [
            { value: 'readability', text: 'Improved rule readability and documentation' },
            { value: 'updates', text: 'Centralized updates (if service changes ports)' },
            { value: 'grouping', text: 'Group related services (HTTP+HTTPS = web-services)' },
            { value: 'performance', text: 'Faster packet processing' },
            { value: 'encryption', text: 'Automatic encryption of traffic' },
            { value: 'prevent_errors', text: 'Prevent typos in port numbers' }
        ],
        correct: ['readability', 'updates', 'grouping', 'prevent_errors'],
        explanation: '📋 Service Objects Best Practice: Create named objects: "HTTPS" = TCP/443, "DNS" = UDP/53+TCP/53, "Web-Services" = HTTP+HTTPS. Benefits: 1) Readability (rule says "allow DNS" not "allow 53/udp"), 2) Maintenance (change "RDP" from 3389 to 13389 in one place, all rules update), 3) Consistency (prevent 443/udp typos), 4) Grouping (SQL-Services = 1433+1434+3306+5432). No performance impact (compiled to ports). Also: Network objects (Web-DMZ = 10.50.0.0/24), schedule objects, application objects (Office365). Object libraries: Export/import across firewalls. Tools: Object hygiene reports (unused objects). Documentation invaluable during audits.'
    },
    {
        id: 'fw65',
        title: 'VPN Split Tunneling Risk',
        points: 8,
        question: 'Remote user connects via VPN with split tunneling enabled. User\'s home network is compromised. What is the risk to corporate network?',
        type: 'radio',
        options: [
            { value: 'pivot_attack', text: 'Attacker pivots from home network through VPN to corporate' },
            { value: 'no_risk', text: 'VPN encryption prevents all risks' },
            { value: 'bandwidth', text: 'Bandwidth consumption only' },
            { value: 'dns_leak', text: 'DNS leaks only' },
            { value: 'user_blocked', text: 'VPN automatically blocks compromised users' }
        ],
        correct: 'pivot_attack',
        explanation: '🚪 Split Tunnel Risk: User laptop has two active routes: Corporate via VPN (10.0.0.0/8), Internet via home ISP. Malware on home network compromises laptop → malware uses VPN connection → pivots to corporate. Full tunnel: ALL traffic through VPN (corporate inspects everything, slower). Split tunnel: Only corporate traffic through VPN (faster, risky). Defense: 1) Endpoint protection mandatory (EDR, AV), 2) NAC (network admission control) checks laptop health before VPN, 3) Zero Trust (never trust network, always verify), 4) Personal firewall on laptop. COVID-19 WFH: Many enabled split tunnel for bandwidth, introduced risk. Trade-off: Performance vs security.'
    },
    {
        id: 'fw66',
        title: 'Broadcast/Multicast Filtering',
        points: 7,
        question: 'Firewall between two network segments. Should broadcast traffic (255.255.255.255) be allowed across firewall?',
        type: 'radio',
        options: [
            { value: 'block_broadcast', text: 'Block - broadcasts should not cross network boundaries' },
            { value: 'allow_all', text: 'Allow all broadcasts for network discovery' },
            { value: 'allow_dhcp', text: 'Allow only DHCP broadcasts' },
            { value: 'routing_forwards', text: 'Routers automatically forward broadcasts' },
            { value: 'multicast_only', text: 'Allow multicast but block broadcast' }
        ],
        correct: 'block_broadcast',
        explanation: '📡 Broadcast Domains: Broadcasts (255.255.255.255, subnet broadcasts) confined to Layer 2 segment. Routers/firewalls do NOT forward broadcasts (by design, prevents broadcast storms). Multicast: Selective forwarding with IGMP/PIM. Use cases: DHCP discover (broadcast), ARP (broadcast), NetBIOS (broadcast). Cross-subnet needs: DHCP relay (unicast to DHCP server), directed broadcasts (sometimes needed for PXE boot, Wake-on-LAN - explicit config). Security: Block broadcast/multicast by default (reduces attack surface), allow specific multicast for routing protocols (OSPF 224.0.0.5/6). Broadcast storms = DoS. Multicast scope: 224.0.0.0/4.'
    },
    {
        id: 'fw67',
        title: 'Firewall Testing Methodology',
        points: 8,
        question: 'After implementing new firewall rules, what is the safest testing approach?',
        type: 'radio',
        options: [
            { value: 'monitor_first', text: 'Deploy in monitor/log-only mode first, analyze traffic, then enforce' },
            { value: 'production_immediately', text: 'Deploy directly to production' },
            { value: 'test_one_rule', text: 'Test one rule at a time with 5-minute intervals' },
            { value: 'disable_logging', text: 'Disable logging to reduce overhead during testing' },
            { value: 'weekend_only', text: 'Only test on weekends' }
        ],
        correct: 'monitor_first',
        explanation: '🧪 Safe Deployment: Phased approach: 1) Lab testing (simulate traffic), 2) Monitor mode (log matches, don\'t enforce - see impact), 3) Pilot (single subnet/user group), 4) Analyze logs (false positives?), 5) Production rollout, 6) Post-implementation review. Monitor mode benefits: Identify legitimate traffic blocked, no service disruption, collect metrics. Tools: Firewall simulators, packet generators, traffic replay. Rollback plan: Save config version, test rollback procedure, define success criteria. After deployment: Monitor for: Connection failures, application errors, helpdesk tickets, firewall logs. Change window: Maintenance window, oncall engineer, stakeholder notification.'
    },
    {
        id: 'fw68',
        title: 'Policy-Based Routing with Firewall',
        points: 9,
        question: 'Different user groups need different internet paths: Executives via ISP-A (low latency), General users via ISP-B (high bandwidth). How to implement?',
        type: 'radio',
        options: [
            { value: 'pbr', text: 'Policy-Based Routing based on source IP/subnet' },
            { value: 'dns', text: 'DNS-based routing only' },
            { value: 'user_choice', text: 'Let users manually choose ISP' },
            { value: 'round_robin', text: 'Round-robin load balancing only' },
            { value: 'firewall_nat', text: 'NAT rules alone' }
        ],
        correct: 'pbr',
        explanation: '🛣️ Policy-Based Routing: Override default routing based on packet characteristics (source IP, destination, port, DSCP, user/group). Example: src=10.10.0.0/24 (exec subnet) → next-hop ISP-A gateway, src=10.20.0.0/16 (general) → ISP-B. vs Load Balancing (distributes traffic). PBR use cases: Multi-ISP (traffic engineering), QoS routing (voice via MPLS, data via internet), compliance (specific traffic via approved path). Implementation: Router/firewall policy routes, SD-WAN (automatic path selection), tag-based routing. Risks: Asymmetric routing, complexity, troubleshooting difficulty. Tools: traceroute, policy route maps, SD-WAN controllers (Meraki, Viptela).'
    },
    {
        id: 'fw69',
        title: 'Firewall Log Analysis',
        points: 7,
        question: 'Firewall logs show 10,000 DENY entries in 1 minute from single source IP to random high ports on your server. What attack is this?',
        type: 'radio',
        options: [
            { value: 'port_scan', text: 'Port scan / reconnaissance' },
            { value: 'ddos', text: 'DDoS attack' },
            { value: 'malware_callback', text: 'Malware C2 beaconing' },
            { value: 'misconfiguration', text: 'Network misconfiguration' },
            { value: 'normal', text: 'Normal traffic pattern' }
        ],
        correct: 'port_scan',
        explanation: '🔍 Port Scan Detection: Attacker probes all 65,535 ports to find open services. Signatures: 1) Many ports, single src→dst, 2) Sequential ports (1,2,3...), 3) High DENY rate, 4) Short time window. Scan types: TCP SYN scan (half-open), TCP connect, UDP scan, Xmas scan, NULL scan, FIN scan. Tools: nmap, masscan, zmap. Defense: 1) Geo-block non-business countries, 2) IPS signatures, 3) Rate limit per-source (block after 100 DENYs/min), 4) Tarpit (slow response), 5) Dark net monitoring. SIEM correlation: Alert on >50 unique ports from single source. Not DDoS (single source, small volume). Logging reveals: Attacker reconnaissance phase (kill chain step 1).'
    },
    {
        id: 'fw70',
        title: 'Egress Data Exfiltration Prevention',
        points: 9,
        question: 'Preventing data exfiltration. Which egress controls are effective? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'dns_filtering', text: 'DNS filtering / DNS tunneling detection' },
            { value: 'ssl_inspect', text: 'SSL/TLS inspection for HTTPS exfil' },
            { value: 'dlp', text: 'DLP (Data Loss Prevention) on firewall' },
            { value: 'block_all_outbound', text: 'Block all outbound traffic' },
            { value: 'file_size_limits', text: 'Limit outbound file transfer sizes' },
            { value: 'uncommon_ports', text: 'Block uncommon high ports (>10000)' }
        ],
        correct: ['dns_filtering', 'ssl_inspect', 'dlp', 'file_size_limits'],
        explanation: '🚨 Data Exfiltration Controls: Layered defense: 1) DNS filtering: Detect DNS tunneling (unusual query patterns, TXT records with data), block DGA domains, 2) SSL inspection: Decrypt HTTPS to inspect for sensitive data (SSN, credit cards), 3) DLP: Scan file uploads for PII/PHI/PCI, watermark tracking, regex matching, 4) File size limits: Flag 10GB upload to personal cloud. Also: 5) Whitelist approved cloud services (Box, not Dropbox), 6) Proxy authentication (who uploaded?), 7) CASB (Cloud Access Security Broker). Exfil channels: HTTPS POST, DNS, ICMP, SMTP, cloud storage, steganography. Monitoring: Baseline normal upload volumes, alert on anomalies. Block all outbound = business killer.'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = firewallExtended;
}
