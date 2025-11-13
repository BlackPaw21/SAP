/**
 * Extended Firewall Questions (fw51-100)
 * Lazy-loaded when user clicks "Load More Questions"
 *
 * Current Status: fw51-60 complete (10 questions)
 * Base questions (fw1-50) are in questions_data.js
 */

const firewallExtended = [
    {
        id: 'fw51',
        title: 'Stateful Firewall Session Table',
        points: 11,
        question: 'Stateful firewall allows outbound HTTP (port 80) but has no inbound allow rule. User browses website. What happens to return traffic?',
        type: 'radio',
        options: [
            { value: 'allowed', text: 'Allowed - firewall tracks session state' },
            { value: 'blocked', text: 'Blocked - no inbound rule exists' },
            { value: 'nat', text: 'Requires NAT to work' },
            { value: 'proxy', text: 'Requires proxy configuration' },
            { value: 'dmz', text: 'Only works from DMZ' }
        ],
        correct: 'allowed',
        explanation: '🔄 Stateful Inspection: Firewall maintains session table tracking connection state (SYN, SYN-ACK, ACK, established, FIN). Outbound SYN creates session entry = return traffic automatically allowed (even without inbound rule). Tracks: TCP flags, sequence numbers, port numbers. vs Stateless: Would require explicit bidirectional rules. Benefits: Fewer rules needed, prevents spoofed responses. Limitations: Memory exhaustion attacks, doesn\'t inspect application layer. Interview: "Stateful vs stateless firewalls?"'
    },
    {
        id: 'fw52',
        title: 'Next-Gen Firewall Features',
        points: 10,
        question: 'What distinguishes Next-Generation Firewall (NGFW) from traditional firewall?',
        type: 'checkbox',
        options: [
            { value: 'app_aware', text: 'Application awareness (identifies apps regardless of port)' },
            { value: 'ips', text: 'Integrated IPS (Intrusion Prevention System)' },
            { value: 'ssl_inspect', text: 'SSL/TLS decryption and inspection' },
            { value: 'user_id', text: 'User identity awareness' },
            { value: 'faster', text: 'Just faster packet filtering' },
            { value: 'cheaper', text: 'Lower cost than traditional firewall' }
        ],
        correct: ['app_aware', 'ips', 'ssl_inspect', 'user_id'],
        explanation: '🔥 NGFW Capabilities: 1) **App awareness**: Identifies Facebook/Skype even on non-standard ports, 2) **Integrated IPS**: Blocks exploits in allowed traffic, 3) **SSL inspection**: Decrypts HTTPS to inspect payload, 4) **User-ID**: Policies based on AD users not just IPs. vs Traditional: Only port/protocol/IP. Vendors: Palo Alto, Fortinet, Cisco Firepower. Challenges: SSL inspection breaks certificate pinning, performance impact. Interview: "NGFW vs WAF vs IPS?"'
    },
    {
        id: 'fw53',
        title: 'Firewall Rule Shadowing',
        points: 12,
        question: 'Firewall rules: (1) DENY any to 10.1.1.0/24 tcp/22, (2) ALLOW 192.168.1.5 to 10.1.1.10 tcp/22. Does 192.168.1.5 have SSH access to 10.1.1.10?',
        type: 'radio',
        options: [
            { value: 'no_shadow', text: 'No - Rule 1 shadows Rule 2 (matches first)' },
            { value: 'yes', text: 'Yes - Rule 2 is more specific' },
            { value: 'depends', text: 'Depends on firewall type' },
            { value: 'both', text: 'Both rules apply (aggregated)' },
            { value: 'error', text: 'Firewall rejects conflicting rules' }
        ],
        correct: 'no_shadow',
        explanation: '🚫 Rule Shadowing: Firewalls process top-to-bottom, first-match-wins. Rule 1 (any→10.1.1.0/24:22 DENY) matches before Rule 2 = shadowed/dead rule. Access denied. Fix: Reorder rules (specific before general), or add exception in Rule 1. Common mistake in large rulesets. Tools: Firewall policy analyzers detect shadowing/redundancy/conflicts. Best practice: Most specific rules first, default deny last. Interview: "Explain firewall rule ordering."'
    },
    {
        id: 'fw54',
        title: 'Zone-Based Firewall Policy',
        points: 11,
        question: 'Zone-based firewall has zones: INSIDE (trusted), DMZ (public servers), OUTSIDE (internet). What is the recommended default policy?',
        type: 'radio',
        options: [
            { value: 'deny_all', text: 'DENY all inter-zone traffic by default, explicit ALLOW needed' },
            { value: 'allow_out', text: 'ALLOW INSIDE→OUTSIDE, deny rest' },
            { value: 'allow_dmz', text: 'ALLOW all DMZ traffic' },
            { value: 'allow_all', text: 'ALLOW all, explicit DENY for threats' },
            { value: 'no_default', text: 'No default policy needed' }
        ],
        correct: 'deny_all',
        explanation: '🛡️ Zone-Based Firewall: Group interfaces into security zones (INSIDE/DMZ/OUTSIDE). Default: DENY all inter-zone traffic = whitelist approach. Then create explicit policies: INSIDE→OUTSIDE allow, OUTSIDE→DMZ allow HTTP/HTTPS, OUTSIDE→INSIDE deny, DMZ→INSIDE deny. Prevents: Compromised DMZ server pivoting to internal network, unauthorized outbound connections. vs Interface-based: More scalable, policy abstraction. Cisco ZBF, Palo Alto security zones. Interview: "Design three-zone firewall architecture."'
    },
    {
        id: 'fw55',
        title: 'NAT Traversal Issues',
        points: 10,
        question: 'FTP client behind NAT firewall connects to external FTP server. Active mode FTP fails but passive mode works. Why?',
        type: 'radio',
        options: [
            { value: 'active_inbound', text: 'Active mode requires inbound connection which NAT blocks' },
            { value: 'passive_faster', text: 'Passive mode is faster' },
            { value: 'port_range', text: 'Active mode uses privileged ports' },
            { value: 'encryption', text: 'Passive mode uses encryption' },
            { value: 'protocol', text: 'Different protocols used' }
        ],
        correct: 'active_inbound',
        explanation: '📂 FTP NAT Traversal: **Active mode**: Client opens port, server connects back (inbound) = NAT/firewall block. **Passive mode**: Client initiates both control + data connections (outbound) = NAT-friendly. NAT issue: Server\'s "PORT" command contains private IP = unreachable. FTP ALG (Application Layer Gateway) in firewall/router rewrites IPs in FTP payload. Similar issues: SIP, H.323, RTSP. Modern: PASV mode default, FTP ALG (or disable ALG if breaks). Interview: "Why does FTP need special firewall handling?"'
    },
    {
        id: 'fw56',
        title: 'Egress Filtering Importance',
        points: 12,
        question: 'Why is egress filtering (outbound) critical even though most attacks are inbound?',
        type: 'checkbox',
        options: [
            { value: 'c2', text: 'Blocks malware C2 (Command & Control) communication' },
            { value: 'exfil', text: 'Prevents data exfiltration' },
            { value: 'lateral', text: 'Limits lateral movement and pivoting' },
            { value: 'compliance', text: 'Required by regulations (PCI-DSS)' },
            { value: 'bandwidth', text: 'Saves bandwidth costs only' },
            { value: 'unnecessary', text: 'Actually not important if inbound is secured' }
        ],
        correct: ['c2', 'exfil', 'lateral', 'compliance'],
        explanation: '🚪 Egress Filtering: Critical for defense-in-depth. Benefits: 1) **Block C2**: Malware can\'t phone home, 2) **Stop exfiltration**: Prevent stolen data upload, 3) **Limit lateral movement**: Compromised host can\'t scan/attack others, 4) **Compliance**: PCI-DSS requires outbound filtering. Default allow outbound = attackers love it. Implement: Whitelist allowed destinations, block known-bad IPs/domains, restrict ports (allow 80/443, deny rest), DNS filtering. Interview: "Ingress vs egress filtering priorities?"'
    },
    {
        id: 'fw57',
        title: 'Firewall High Availability',
        points: 11,
        question: 'Active/Active firewall HA pair - what is the primary challenge?',
        type: 'radio',
        options: [
            { value: 'state_sync', text: 'Session state synchronization between firewalls' },
            { value: 'cost', text: 'Higher licensing cost' },
            { value: 'complexity', text: 'Configuration complexity' },
            { value: 'bandwidth', text: 'Bandwidth limitations' },
            { value: 'latency', text: 'Increased latency' }
        ],
        correct: 'state_sync',
        explanation: '🔄 Firewall HA: **Active/Active**: Both process traffic (load sharing). Challenge: Session state must sync in real-time. If Firewall A fails mid-session, Firewall B needs session table to continue. Asymmetric routing breaks stateful inspection. **Active/Passive**: Standby takes over (simpler, session table copied). Sync methods: Hardware state link, config sync. Failure scenarios: Split-brain (both become active), sync lag (sessions dropped). Vendors: Palo Alto HA, Fortinet cluster, Checkpoint ClusterXL. Interview: "HA architectures and trade-offs."'
    },
    {
        id: 'fw58',
        title: 'Micro-segmentation Benefits',
        points: 13,
        question: 'Organization implements micro-segmentation with host-based firewalls on every server. What security benefit does this provide over traditional perimeter firewall?',
        type: 'radio',
        options: [
            { value: 'east_west', text: 'Controls east-west traffic (server-to-server) inside network' },
            { value: 'faster', text: 'Faster packet processing' },
            { value: 'cheaper', text: 'Lower cost than network firewalls' },
            { value: 'compliance', text: 'Automatically meets all compliance' },
            { value: 'encryption', text: 'Provides encryption for all traffic' }
        ],
        correct: 'east_west',
        explanation: '🧱 Micro-segmentation: Traditional perimeter firewall = castle model (hard outer shell, soft inside). Micro-segmentation: Firewall rules on every workload/VM/container. Benefits: 1) **East-west security**: Server-to-server traffic controlled (not trusted by default), 2) **Contain breaches**: Compromised host can\'t pivot freely, 3) **Zero-trust**: Verify every connection. Technologies: VMware NSX, Cisco ACI, Illumio, Windows Firewall + GPO. Challenge: Policy management at scale. Interview: "Traditional segmentation vs micro-segmentation?"'
    },
    {
        id: 'fw59',
        title: 'Firewall Evasion Techniques',
        points: 12,
        question: 'Attacker fragments packets into very small pieces to evade firewall inspection. What is this attack called?',
        type: 'radio',
        options: [
            { value: 'fragmentation', text: 'Fragmentation attack / tiny fragments' },
            { value: 'smuggling', text: 'HTTP smuggling' },
            { value: 'tunneling', text: 'Protocol tunneling' },
            { value: 'polymorphic', text: 'Polymorphic shellcode' },
            { value: 'encoding', text: 'Encoding obfuscation' }
        ],
        correct: 'fragmentation',
        explanation: '💥 Fragmentation Evasion: Send payload in tiny IP fragments (8 bytes each). Firewall inspects first fragment (only headers visible), passes fragments, target reassembles malicious payload. Also: Overlapping fragments, timeout exploitation. Defense: Fragment reassembly before inspection (most modern firewalls do this), minimum fragment size enforcement, drop suspicious fragmentation. Tools: Fragroute, Nmap --mtu. Related: TCP segmentation evasion. IDS/IPS must reassemble too. Interview: "Firewall evasion techniques?"'
    },
    {
        id: 'fw60',
        title: 'Geo-blocking Effectiveness',
        points: 9,
        question: 'Firewall blocks all traffic from countries X, Y, Z based on GeoIP. What are the limitations?',
        type: 'checkbox',
        options: [
            { value: 'vpn', text: 'Attackers use VPNs/proxies to bypass' },
            { value: 'accuracy', text: 'GeoIP databases not 100% accurate' },
            { value: 'cloud', text: 'Cloud services IP ranges span multiple countries' },
            { value: 'dynamic', text: 'IP addresses change ownership/location' },
            { value: 'perfect', text: 'No limitations - geo-blocking is perfect' }
        ],
        correct: ['vpn', 'accuracy', 'cloud', 'dynamic'],
        explanation: '🌍 Geo-blocking Limitations: 1) **VPN/proxy bypass**: Attackers route through allowed countries, 2) **GeoIP inaccuracy**: ~95-99% accurate (not perfect), mobile carriers, satellites misclassified, 3) **Cloud services**: AWS/Azure IPs globally distributed, blocking region blocks services, 4) **IP mobility**: Addresses reassigned, databases lag. Use cases: Reduce attack surface (block countries with no business presence), compliance (data residency). Not a primary security control. Databases: MaxMind, IP2Location. Interview: "When is geo-blocking appropriate?"'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = firewallExtended;
}
