/**
 * Extended Networking Questions (net51-100)
 * Lazy-loaded when user clicks "Load More Questions"
 */

const networkingExtended = [
    {
        id: 'net71',
        title: 'BGP Hijacking Detection',
        points: 13,
        question: 'You observe routes to your company\'s IP prefix (203.0.113.0/24) now pointing to an AS in another country. What attack is this?',
        type: 'radio',
        options: [
            { value: 'bgp_hijack', text: 'BGP hijacking - route announcement attack' },
            { value: 'dns', text: 'DNS hijacking' },
            { value: 'mitm', text: 'Man-in-the-middle attack' },
            { value: 'misconfiguration', text: 'Simple routing misconfiguration' },
            { value: 'legit', text: 'Legitimate CDN routing' }
        ],
        correct: 'bgp_hijack',
        explanation: '🚨 BGP Hijacking: Attacker announces your IP prefixes from their AS, redirecting internet traffic. BGP trusts announcements without verification. Impact: Traffic interception, blackholing, spam/phishing. Famous: Pakistan Telecom hijacked YouTube (2008), China Telecom incidents. Defense: ROA (Route Origin Authorization), RPKI, BGP monitoring services, prefix filtering. Tools: BGPmon, RIPE RIS. Interview: "How do you detect BGP hijacking?" (BGP alert services, traceroute anomalies, traffic drops).'
    },
    {
        id: 'net72',
        title: 'TCP Connection State',
        points: 9,
        question: 'Netstat shows connection in "TIME_WAIT" state for 60 seconds. What does this mean?',
        type: 'radio',
        options: [
            { value: 'normal', text: 'Normal - waiting for delayed packets to expire' },
            { value: 'attack', text: 'DoS attack in progress' },
            { value: 'hung', text: 'Connection hung/frozen' },
            { value: 'error', text: 'Network error' },
            { value: 'firewall', text: 'Firewall blocking connection' }
        ],
        correct: 'normal',
        explanation: '⏳ TIME_WAIT: Normal TCP state after active close (sent FIN). Waits 2×MSL (Maximum Segment Lifetime = 2 minutes default) to ensure all packets cleared before reusing port. Prevents old packets from interfering with new connections. High TIME_WAIT count = many short connections (web servers normal). Not an attack. Tuning: Reduce tcp_fin_timeout (Linux), enable tcp_tw_reuse. Interview: "Why does TIME_WAIT exist?" (Prevent packet confusion between old/new connections).'
    },
    {
        id: 'net73',
        title: 'VXLAN Purpose',
        points: 11,
        question: 'What problem does VXLAN solve?',
        type: 'radio',
        options: [
            { value: 'vlan_limit', text: 'Overcome 4096 VLAN limit - supports 16M networks' },
            { value: 'security', text: 'Improve network security' },
            { value: 'speed', text: 'Increase network speed' },
            { value: 'firewall', text: 'Replace firewalls' },
            { value: 'routing', text: 'Improve routing efficiency' }
        ],
        correct: 'vlan_limit',
        explanation: '🌐 VXLAN (Virtual Extensible LAN): Overcomes 802.1Q VLAN limit of 4096. Uses 24-bit VNID = 16 million virtual networks. Encapsulates Layer 2 Ethernet frames in UDP (port 4789). Use cases: Cloud (multi-tenant isolation), datacenter fabric, overlay networks. Cisco ACI, VMware NSX use VXLAN. Alternative: NVGRE, GENEVE. Interview: "Why do cloud providers need VXLAN?" (Massive scale, tenant isolation). Wireshark can decode VXLAN.'
    },
    {
        id: 'net74',
        title: 'IPv6 Neighbor Discovery',
        points: 10,
        question: 'IPv6 uses NDP (Neighbor Discovery Protocol) instead of ARP. What protocol does NDP use?',
        type: 'radio',
        options: [
            { value: 'icmpv6', text: 'ICMPv6 - Internet Control Message Protocol v6' },
            { value: 'tcp', text: 'TCP' },
            { value: 'udp', text: 'UDP' },
            { value: 'arp', text: 'ARP' },
            { value: 'dhcp', text: 'DHCPv6' }
        ],
        correct: 'icmpv6',
        explanation: '🔍 NDP uses ICMPv6: Neighbor Solicitation (Type 135) = "Who has this IPv6?", Neighbor Advertisement (Type 136) = "I have it". Also: Router Solicitation/Advertisement, Redirect. NDP is more efficient than ARP (multicast vs broadcast). Security issue: No authentication = vulnerable to spoofing. Defense: RA Guard, SEND (Secure NDP - rarely deployed). Interview: "How is IPv6 different from IPv4?" NDP vs ARP is key difference.'
    },
    {
        id: 'net75',
        title: 'TCP Connection Establishment',
        points: 7,
        question: 'Client initiates connection, receives SYN-ACK with MSS=1460. What does MSS indicate?',
        type: 'radio',
        options: [
            { value: 'data_size', text: 'Maximum data size per TCP segment (excludes headers)' },
            { value: 'window', text: 'Window size' },
            { value: 'bandwidth', text: 'Maximum bandwidth' },
            { value: 'mtu', text: 'MTU size' },
            { value: 'buffer', text: 'Buffer size' }
        ],
        correct: 'data_size',
        explanation: '📏 MSS (Maximum Segment Size): Largest amount of data in single TCP segment. 1460 = typical for Ethernet (1500 MTU - 20 IP header - 20 TCP header). Negotiated during handshake. Prevents fragmentation. MSS ≠ MTU (MSS is payload only). If MSS too large = fragmentation = performance hit. Path MTU Discovery adjusts MSS. Common interview question. Check: Wireshark shows MSS in SYN packets.'
    },
    {
        id: 'net76',
        title: 'SYN Cookies',
        points: 12,
        question: 'What is the purpose of SYN cookies?',
        type: 'radio',
        options: [
            { value: 'syn_flood', text: 'Defend against SYN flood without storing state' },
            { value: 'authentication', text: 'Authenticate TCP connections' },
            { value: 'encryption', text: 'Encrypt TCP handshake' },
            { value: 'fast_connect', text: 'Speed up connection establishment' },
            { value: 'tracking', text: 'Track user sessions' }
        ],
        correct: 'syn_flood',
        explanation: '🍪 SYN Cookies: Cryptographically encode connection info in sequence number, eliminating SYN_RCVD state. Normal: SYN → allocate resources → vulnerable to flood. SYN cookies: SYN → compute cookie → no state until ACK. Tradeoff: Can\'t use TCP options (window scaling, SACK). Enabled automatically under attack in Linux (net.ipv4.tcp_syncookies = 1). Interview: "How do you defend against SYN floods?" SYN cookies + rate limiting + firewall. Modern defense: still relevant.'
    },
    {
        id: 'net77',
        title: 'Asymmetric Routing',
        points: 10,
        question: 'Firewall drops packets from established connection. Logs show: "SYN from 10.1.1.5 to 192.168.1.10 ALLOWED, but SYN-ACK from 192.168.1.10 to 10.1.1.5 DENIED - no session". What is wrong?',
        type: 'radio',
        options: [
            { value: 'asymmetric', text: 'Asymmetric routing - return path bypasses stateful firewall' },
            { value: 'misconfigured', text: 'Firewall rules misconfigured' },
            { value: 'spoofed', text: 'Spoofed packets' },
            { value: 'nat', text: 'NAT issue' },
            { value: 'mtu', text: 'MTU problem' }
        ],
        correct: 'asymmetric',
        explanation: '🔄 Asymmetric Routing: Outbound through Firewall A, return through Firewall B. Stateful firewall expects reply through same path. SYN creates session entry, but SYN-ACK returns via different path = no session found = DROP. Common in: Complex networks, load balancers, BGP. Solutions: Session sync between firewalls, stateless ACLs, route symmetry. Debug: Packet captures on both paths. Interview: "Why would a firewall drop legitimate traffic?" Asymmetric routing is #1 reason.'
    },
    {
        id: 'net78',
        title: 'ECN (Explicit Congestion Notification)',
        points: 11,
        question: 'What does ECN do?',
        type: 'radio',
        options: [
            { value: 'congestion', text: 'Signal congestion without dropping packets' },
            { value: 'encryption', text: 'Encrypt network traffic' },
            { value: 'compression', text: 'Compress data' },
            { value: 'authentication', text: 'Authenticate connections' },
            { value: 'error_check', text: 'Enhanced error checking' }
        ],
        correct: 'congestion',
        explanation: '📊 ECN (RFC 3168): Routers mark IP packets (CE bit) instead of dropping when congested. TCP sender reduces sending rate without packet loss. Without ECN: Drop packets to signal congestion = retransmissions. With ECN: Set CE bit = smooth rate reduction. Benefits: Lower latency, better throughput. Requires: ECN support on hosts + routers. Enable: Linux (net.ipv4.tcp_ecn = 1). Wireshark: IP header ECN bits. Advanced TCP optimization for interview.'
    },
    {
        id: 'net79',
        title: 'Smurf Attack',
        points: 9,
        question: 'What is a Smurf attack?',
        type: 'radio',
        options: [
            { value: 'icmp_amp', text: 'ICMP echo requests to broadcast - amplification DDoS' },
            { value: 'syn_flood', text: 'SYN flood attack' },
            { value: 'dns_amp', text: 'DNS amplification' },
            { value: 'malware', text: 'Malware infection' },
            { value: 'sniffing', text: 'Packet sniffing attack' }
        ],
        correct: 'icmp_amp',
        explanation: '💥 Smurf Attack: Send ICMP echo request to broadcast address with spoofed source = victim\'s IP. All hosts reply to victim = amplification. 100:1 amplification ratio. Defense: Block directed broadcast (no ip directed-broadcast on Cisco), egress filtering (prevent source IP spoofing). Modern: Mostly mitigated by ISPs blocking broadcasts. Historical but still tested in interviews. Similar: Fraggle (UDP), NTP/DNS reflection (modern amplification).'
    },
    {
        id: 'net80',
        title: 'Path MTU Discovery',
        points: 10,
        question: 'Application sends 5000-byte packets. Router drops them and sends ICMP "Fragmentation Needed, DF set" (Type 3 Code 4). What should application do?',
        type: 'radio',
        options: [
            { value: 'reduce_mtu', text: 'Reduce packet size to accommodate smaller MTU in path' },
            { value: 'disable_df', text: 'Disable DF (Don\'t Fragment) flag' },
            { value: 'retry', text: 'Retry sending same packet' },
            { value: 'ignore', text: 'Ignore the ICMP message' },
            { value: 'tcp_only', text: 'Switch to TCP' }
        ],
        correct: 'reduce_mtu',
        explanation: '🛤️ Path MTU Discovery: Find smallest MTU along path. App sets DF flag, sends large packet. If router can\'t forward (MTU too small) = ICMP Frag Needed. App reduces size, retries. Prevents fragmentation = better performance. PMTUD Blackhole: Firewall blocks ICMP = app never learns = connection hangs. Solution: MSS clamping, allow ICMP Type 3 Code 4. Interview: "Why does my VPN connection hang?" Common PMTUD blackhole issue. Debug: tcpdump icmp.'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = networkingExtended;
}
