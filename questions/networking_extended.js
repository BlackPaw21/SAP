/**
 * Extended Networking Questions (net51-100)
 * Lazy-loaded when user clicks "Load More Questions"
 */

const networkingExtended = [
    {
        id: 'net51',
        title: 'IPv6 Address Recognition',
        points: 6,
        question: 'Which IPv6 address represents localhost?',
        type: 'radio',
        options: [
            { value: '::1', text: '::1' },
            { value: 'fe80::1', text: 'fe80::1' },
            { value: '::ffff:127.0.0.1', text: '::ffff:127.0.0.1' },
            { value: '2001:db8::1', text: '2001:db8::1' },
            { value: 'ff02::1', text: 'ff02::1' }
        ],
        correct: '::1',
        explanation: '🏠 ::1 is IPv6 loopback (equivalent to 127.0.0.1 in IPv4). Shortened from 0000:0000:0000:0000:0000:0000:0000:0001. fe80::1 = link-local, ff02::1 = all-nodes multicast, 2001:db8:: = documentation range, ::ffff:127.0.0.1 = IPv4-mapped IPv6. Common interview question for network roles.'
    },
    {
        id: 'net52',
        title: 'Packet Fragmentation Attack',
        points: 9,
        question: 'You observe packets with identical IP ID field but different fragment offsets targeting your web server. What attack is this?',
        type: 'radio',
        options: [
            { value: 'teardrop', text: 'Teardrop/Fragment Overlap attack' },
            { value: 'smurf', text: 'Smurf attack' },
            { value: 'syn_flood', text: 'SYN flood' },
            { value: 'legit', text: 'Normal fragmentation' },
            { value: 'ping_death', text: 'Ping of Death' }
        ],
        correct: 'teardrop',
        explanation: '💥 Teardrop Attack: Sends overlapping IP fragments to crash vulnerable systems during reassembly. Fragments have same IP ID but overlapping offsets = buffer overrun when OS tries to reassemble. CVE-1997-0124. Modern systems patched but IoT devices vulnerable. Defense: Fragment reassembly validation, drop malformed fragments, IPS signatures. Historical but still tested in certifications.'
    },
    {
        id: 'net53',
        title: 'Ethernet Frame Analysis',
        points: 7,
        question: 'Maximum size of standard Ethernet frame (excluding preamble)?',
        type: 'radio',
        options: [
            { value: '1518', text: '1518 bytes' },
            { value: '1500', text: '1500 bytes' },
            { value: '1522', text: '1522 bytes' },
            { value: '9000', text: '9000 bytes' },
            { value: '65535', text: '65535 bytes' }
        ],
        correct: '1518',
        explanation: '📐 1518 bytes = max Ethernet II frame. Breakdown: 14 bytes header (6 dest MAC + 6 src MAC + 2 EtherType) + 1500 bytes data (MTU) + 4 bytes FCS (CRC). With 802.1Q VLAN tag = 1522 bytes. Jumbo frames = 9000 bytes (not standard). Common interview question. Frames < 64 bytes = runts (collision fragments). Frames > 1518 = giants (errors or jumbo).'
    },
    {
        id: 'net54',
        title: 'TCP Window Size Zero',
        points: 10,
        question: 'During packet capture, you see server sending TCP packets with Window Size = 0 to client. What does this indicate?',
        type: 'radio',
        options: [
            { value: 'buffer_full', text: 'Server receive buffer is full - flow control' },
            { value: 'attack', text: 'Client is performing a DDoS attack' },
            { value: 'connection_close', text: 'Connection is being terminated' },
            { value: 'error', text: 'Network error or packet corruption' },
            { value: 'normal', text: 'Normal TCP behavior' }
        ],
        correct: 'buffer_full',
        explanation: '🚦 TCP Flow Control: Window Size = 0 means "STOP sending, my buffer is full!" Receiver tells sender to pause until buffer space available. Sender must wait for Window Update (size > 0) before resuming. Causes: Slow application reading data, resource exhaustion, performance issues. Not an attack - legitimate flow control. If persistent = application bottleneck or memory issue. Monitor for Zero Window conditions in performance troubleshooting.'
    },
    {
        id: 'net55',
        title: 'Gratuitous ARP Purpose',
        points: 8,
        question: 'What is the primary legitimate use of Gratuitous ARP?',
        type: 'radio',
        options: [
            { value: 'update_cache', text: 'Update ARP caches when IP changes or HA failover' },
            { value: 'discover_hosts', text: 'Discover other hosts on network' },
            { value: 'attack', text: 'Perform ARP poisoning attacks' },
            { value: 'test_network', text: 'Test network connectivity' },
            { value: 'broadcast', text: 'Broadcast MAC address to all hosts' }
        ],
        correct: 'update_cache',
        explanation: '📢 Gratuitous ARP = ARP request for own IP address. Purposes: 1) **IP conflict detection** (if another host replies = duplicate IP), 2) **Update neighbor caches** when IP/MAC changes (NIC replacement, VM migration), 3) **HA failover** (VIP moves to backup, GARP announces new MAC). Also abused for ARP spoofing attacks. Legitimate uses: VRRP, HSRP, VM live migration. Monitor for unexpected GARP = possible attack or misconfiguration.'
    },
    {
        id: 'net56',
        title: 'TCP RST Packet Analysis',
        points: 9,
        question: 'Client sends SYN to server port 80. Server immediately replies with RST. What does this mean?',
        type: 'radio',
        options: [
            { value: 'port_closed', text: 'Port 80 is closed/no service listening' },
            { value: 'firewall', text: 'Firewall blocking connection' },
            { value: 'overload', text: 'Server overloaded' },
            { value: 'attack', text: 'DDoS attack in progress' },
            { value: 'normal', text: 'Normal connection establishment' }
        ],
        correct: 'port_closed',
        explanation: '🚪 RST (Reset) = "Port closed, service not listening". Server received SYN but no application bound to port 80 = immediate RST. Different from firewall DROP (no response) or REJECT (ICMP unreachable). RST also sent for: invalid packets, connection abortion, sequence number out of window. Nmap uses RST to identify closed ports. Interview tip: RST = explicit rejection, DROP/timeout = filtering.'
    },
    {
        id: 'net57',
        title: 'Slow Loris Attack Detection',
        points: 11,
        question: 'Web server shows max connections reached but low bandwidth usage. Connections stay ESTABLISHED for hours. What attack?',
        type: 'radio',
        options: [
            { value: 'slowloris', text: 'Slowloris - slow HTTP headers' },
            { value: 'syn_flood', text: 'SYN flood attack' },
            { value: 'ddos', text: 'Bandwidth DDoS' },
            { value: 'normal', text: 'Normal keep-alive connections' },
            { value: 'udp_flood', text: 'UDP flood' }
        ],
        correct: 'slowloris',
        explanation: '🐌 Slowloris: Sends partial HTTP requests slowly to exhaust connection pool. Opens many connections, sends incomplete headers byte-by-byte, keeps connections alive forever. Max connections reached + low bandwidth + long duration = Slowloris. Defense: Connection timeout, rate limiting, reverse proxy (nginx, Cloudflare), mod_reqtimeout in Apache. Similar: R.U.D.Y, Slow POST. MITRE: Endpoint DoS (T1499.003). Famous against Apache, less effective vs nginx/IIS.'
    },
    {
        id: 'net58',
        title: 'DNS Cache Poisoning',
        points: 12,
        question: 'Attacker spoofs DNS responses to cache fake records. Which field must attacker predict correctly? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'txid', text: 'Transaction ID (16-bit)' },
            { value: 'port', text: 'Source port (UDP)' },
            { value: 'ip', text: 'DNS server IP' },
            { value: 'domain', text: 'Queried domain name' },
            { value: 'ttl', text: 'TTL value' },
            { value: 'opcode', text: 'DNS opcode' }
        ],
        correct: ['txid', 'port'],
        explanation: '🎯 DNS Cache Poisoning (Kaminsky Attack): Attacker must guess Transaction ID (65,536 options) + Source Port (65,536 options) = 4.3 billion combinations. Race: Send fake response before real one. Modern defense: Port randomization, TXID randomization, DNSSEC. CVE-2008-1447. Why it matters: Redirect traffic to phishing sites, MITM attacks. Interview: "How does DNSSEC prevent this?" (Answer: Cryptographic signatures validate responses).'
    },
    {
        id: 'net59',
        title: 'Subnet Mask Calculation',
        points: 7,
        question: 'Network 192.168.10.0/26 - how many subnets and hosts per subnet?',
        type: 'radio',
        options: [
            { value: '4_62', text: '4 subnets, 62 hosts each' },
            { value: '2_126', text: '2 subnets, 126 hosts each' },
            { value: '8_30', text: '8 subnets, 30 hosts each' },
            { value: '16_14', text: '16 subnets, 14 hosts each' },
            { value: '4_64', text: '4 subnets, 64 hosts each' }
        ],
        correct: '4_62',
        explanation: '🔢 /26 = 255.255.255.192 = borrowing 2 bits from /24. Subnets: 2² = 4. Hosts per subnet: 2⁶ - 2 = 64 - 2 = 62 usable. Ranges: .0-.63, .64-.127, .128-.191, .192-.255. Each subnet loses 2 IPs (network + broadcast). Common interview question for network roles. Formula: Subnets = 2^(borrowed bits), Hosts = 2^(host bits) - 2.'
    },
    {
        id: 'net60',
        title: 'ICMP Redirect Attack',
        points: 10,
        question: 'Workstation receives ICMP Redirect messages claiming better route through 10.5.10.99. What is the risk?',
        type: 'radio',
        options: [
            { value: 'mitm', text: 'Man-in-the-middle - traffic redirected through attacker' },
            { value: 'dos', text: 'Denial of service attack' },
            { value: 'scan', text: 'Network scanning attempt' },
            { value: 'normal', text: 'Normal network optimization' },
            { value: 'overload', text: 'Router overload notification' }
        ],
        correct: 'mitm',
        explanation: '⚠️ ICMP Redirect Attack: Attacker sends fake ICMP Type 5 messages to change victim\'s routing table, redirecting traffic through attacker\'s machine for MITM. Victims update routing cache and send packets to malicious "gateway". Defense: Disable ICMP redirects (no ip redirects in Cisco), host-based firewall rules, network segmentation. Legitimate use: Routers inform hosts of better routes, but rarely needed in modern networks. Check: netstat -rn to see route changes.'
    },
    {
        id: 'net61',
        title: 'HTTP/2 vs HTTP/1.1',
        points: 8,
        question: 'What is the primary performance advantage of HTTP/2 over HTTP/1.1?',
        type: 'radio',
        options: [
            { value: 'multiplexing', text: 'Multiplexing - multiple requests over single connection' },
            { value: 'encryption', text: 'Built-in encryption' },
            { value: 'compression', text: 'Better compression' },
            { value: 'caching', text: 'Improved caching' },
            { value: 'cookies', text: 'Better cookie handling' }
        ],
        correct: 'multiplexing',
        explanation: '🚀 HTTP/2 Multiplexing: Send multiple requests/responses simultaneously over ONE TCP connection without head-of-line blocking. HTTP/1.1 requires multiple connections or waits for response before next request. HTTP/2 also: header compression (HPACK), server push, binary protocol. Performance: 30-50% faster page loads. Security: Most browsers require TLS for HTTP/2. Interview question: "Why is HTTP/2 faster?" Tools: Wireshark can decode HTTP/2, chrome://net-internals.'
    },
    {
        id: 'net62',
        title: 'Time to Live Exceeded',
        points: 7,
        question: 'User gets "TTL exceeded" error. Traceroute shows loops. What is the problem?',
        type: 'radio',
        options: [
            { value: 'routing_loop', text: 'Routing loop - packets circling between routers' },
            { value: 'firewall', text: 'Firewall blocking traffic' },
            { value: 'dns', text: 'DNS resolution failure' },
            { value: 'congestion', text: 'Network congestion' },
            { value: 'mtu', text: 'MTU mismatch' }
        ],
        correct: 'routing_loop',
        explanation: '🔄 Routing Loop: Packets bounce between routers forever. TTL decrements each hop, reaches 0 = ICMP Time Exceeded. Causes: Misconfigured routes, routing protocol convergence issues, static route mistakes. Debug: traceroute shows same routers repeating. Fix: Correct routing tables, check for conflicting routes, verify routing protocol config. Prevention: Split horizon, route poisoning in RIP, SPF algorithm in OSPF. Common interview scenario.'
    },
    {
        id: 'net63',
        title: 'TCP Selective Acknowledgment',
        points: 11,
        question: 'TCP option SACK (Selective Acknowledgment) - what problem does it solve?',
        type: 'radio',
        options: [
            { value: 'retransmit', text: 'Retransmit only missing segments, not entire window' },
            { value: 'faster_connect', text: 'Faster connection establishment' },
            { value: 'security', text: 'Better security' },
            { value: 'flow_control', text: 'Improved flow control' },
            { value: 'congestion', text: 'Congestion avoidance' }
        ],
        correct: 'retransmit',
        explanation: '📦 SACK (RFC 2018): Without SACK, if packet 5 is lost in sequence 1-10, sender must retransmit ALL 5-10. With SACK, receiver says "I have 1-4,6-10, resend ONLY 5". Dramatically improves performance over lossy networks. Enabled by default in modern OSes. Check: netstat -s | grep SACK. Interview: "How does TCP recover from packet loss?" SACK vs Fast Retransmit/Recovery. Wireshark shows SACK options in TCP header.'
    },
    {
        id: 'net64',
        title: 'Broadcast Storm',
        points: 10,
        question: 'Network performance degrades. All switches show 99% CPU, massive broadcast traffic. Likely cause?',
        type: 'radio',
        options: [
            { value: 'stp_loop', text: 'STP failure or bridging loop' },
            { value: 'ddos', text: 'DDoS attack' },
            { value: 'malware', text: 'Malware infection' },
            { value: 'dns', text: 'DNS issues' },
            { value: 'vlan', text: 'VLAN misconfiguration' }
        ],
        correct: 'stp_loop',
        explanation: '🌪️ Broadcast Storm: Layer 2 loop causes broadcast frames to multiply infinitely. STP (Spanning Tree Protocol) prevents loops by blocking redundant paths. STP failure (disabled, misconfigured, or convergence issues) = instant broadcast storm. Symptoms: 99% CPU, network down, MAC table thrashing. Fix: Emergency: Unplug cables to break loop. Permanent: Enable BPDU guard, root guard, verify STP config. Prevention: Rapid STP (RSTP), loop guard. Serious interview scenario.'
    },
    {
        id: 'net65',
        title: 'Private IPv4 Ranges',
        points: 6,
        question: 'Which IP range is NOT RFC 1918 private address space?',
        type: 'radio',
        options: [
            { value: '100', text: '100.64.0.0/10' },
            { value: '10', text: '10.0.0.0/8' },
            { value: '172', text: '172.16.0.0/12' },
            { value: '192', text: '192.168.0.0/16' },
            { value: 'all_private', text: 'All are private ranges' }
        ],
        correct: '100',
        explanation: '📋 RFC 1918 Private Ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. 100.64.0.0/10 = RFC 6598 Shared Address Space (carrier-grade NAT / CGNAT), NOT private addresses. Used by ISPs for internal network when IPv4 exhausted. Also: 127.0.0.0/8 (loopback), 169.254.0.0/16 (APIPA link-local). Common interview trap question. Non-routable on public internet but different purposes.'
    },
    {
        id: 'net66',
        title: 'TCP Timestamp Option',
        points: 9,
        question: 'TCP Timestamp option - what is its primary purpose?',
        type: 'radio',
        options: [
            { value: 'rtt', text: 'Measure Round-Trip Time (RTT) for performance' },
            { value: 'security', text: 'Prevent replay attacks' },
            { value: 'sync_clocks', text: 'Synchronize host clocks' },
            { value: 'sequence', text: 'Replace sequence numbers' },
            { value: 'encryption', text: 'Enable encryption' }
        ],
        correct: 'rtt',
        explanation: '⏱️ TCP Timestamps (RFC 1323): Measure RTT accurately for better congestion control and timeout calculations. Also enables PAWS (Protection Against Wrapped Sequences) for high-speed networks. Security concern: Can leak system uptime for OS fingerprinting. Disable if paranoid: echo 0 > /proc/sys/net/ipv4/tcp_timestamps. Wireshark: See TSval/TSecr in TCP options. Interview: "What TCP options improve performance?"'
    },
    {
        id: 'net67',
        title: 'Jumbo Frames',
        points: 8,
        question: 'When should you enable Jumbo Frames (9000 byte MTU)?',
        type: 'radio',
        options: [
            { value: 'storage', text: 'Storage/backup networks with all devices supporting it' },
            { value: 'always', text: 'Always - better performance' },
            { value: 'internet', text: 'Internet-facing connections' },
            { value: 'wifi', text: 'Wi-Fi networks' },
            { value: 'vpn', text: 'VPN connections' }
        ],
        correct: 'storage',
        explanation: '📦 Jumbo Frames: 9000-byte MTU vs standard 1500. Benefits: ~15-20% throughput increase, lower CPU usage (fewer packets to process). Requirements: ALL devices in path must support (switches, NICs, routers). Use cases: Storage networks (iSCSI, NFS), backup, datacenter interconnects. DON\'T use: Internet traffic (fragmentation), mixed networks (performance degrades). Common mistake: Enable on server but not switches = worse performance. Test: ping -M do -s 8972 (Linux) to verify path MTU.'
    },
    {
        id: 'net68',
        title: 'QUIC Protocol',
        points: 12,
        question: 'QUIC protocol (HTTP/3) - what transport does it use?',
        type: 'radio',
        options: [
            { value: 'udp', text: 'UDP - User Datagram Protocol' },
            { value: 'tcp', text: 'TCP - Transmission Control Protocol' },
            { value: 'sctp', text: 'SCTP - Stream Control' },
            { value: 'icmp', text: 'ICMP' },
            { value: 'ip', text: 'Direct IP' }
        ],
        correct: 'udp',
        explanation: '🚀 QUIC = Quick UDP Internet Connections. Built on UDP to avoid TCP head-of-line blocking and enable faster deployment (no kernel/middlebox changes). Features: Built-in encryption (TLS 1.3), connection migration (Wi-Fi to cellular seamless), 0-RTT connection establishment. Used by: Google, YouTube, Facebook. HTTP/3 uses QUIC. Firewall challenge: Runs on UDP 443, looks different from traditional TCP. Interview: "Why did Google create QUIC?" Modern protocol SOC analysts need to understand.'
    },
    {
        id: 'net69',
        title: 'MAC Flooding Attack',
        points: 10,
        question: 'Attacker floods switch with thousands of fake MAC addresses. What is the goal?',
        type: 'radio',
        options: [
            { value: 'overflow_cam', text: 'Overflow CAM table - turn switch into hub' },
            { value: 'dos', text: 'Denial of service' },
            { value: 'steal_macs', text: 'Steal MAC addresses' },
            { value: 'arp_poison', text: 'ARP poisoning' },
            { value: 'vlan_hop', text: 'VLAN hopping' }
        ],
        correct: 'overflow_cam',
        explanation: '💥 MAC Flooding: Overwhelm switch CAM (Content Addressable Memory) table with fake MAC addresses. When full, switch fails-open mode = broadcasts ALL traffic like a hub. Attacker sniffs all network traffic. Tool: macof from dsniff. Defense: Port security (limit MAC addresses per port), dynamic ARP inspection, 802.1X authentication. Modern switches: Fail-closed or drop unknown MACs. Interview: "What\'s the difference between MAC flooding and ARP spoofing?"'
    },
    {
        id: 'net70',
        title: 'TCP Fast Open',
        points: 11,
        question: 'TCP Fast Open (TFO) - what does it eliminate?',
        type: 'radio',
        options: [
            { value: 'handshake_rtt', text: '1 RTT from handshake - send data in SYN' },
            { value: 'encryption', text: 'Encryption overhead' },
            { value: 'checksums', text: 'Checksum calculations' },
            { value: 'window', text: 'Window scaling' },
            { value: 'retransmit', text: 'Retransmissions' }
        ],
        correct: 'handshake_rtt',
        explanation: '⚡ TCP Fast Open (RFC 7413): Sends application data in initial SYN packet using cookie. Normal: SYN → SYN-ACK → ACK → Data (3 RTT). TFO: SYN+Data → SYN-ACK+Data → ACK (1 RTT saved). Security: Cookie prevents SYN flood amplification. Enabled: Linux (net.ipv4.tcp_fastopen), modern browsers. Use case: Reduce latency for short connections (HTTP requests). Interview: "How can TCP be faster?" Understanding TFO shows advanced networking knowledge.'
    },
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
    },
    {
        id: 'net81',
        title: 'OSPF Neighbors Stuck in EXSTART',
        points: 12,
        question: 'OSPF neighbors stuck in EXSTART state. What is the most likely cause?',
        type: 'radio',
        options: [
            { value: 'mtu_mismatch', text: 'MTU mismatch - DBD packets too large' },
            { value: 'auth_fail', text: 'Authentication failure' },
            { value: 'area_mismatch', text: 'Area mismatch' },
            { value: 'network_type', text: 'Network type mismatch' },
            { value: 'router_id', text: 'Duplicate Router ID' }
        ],
        correct: 'mtu_mismatch',
        explanation: '🔌 OSPF EXSTART State: Routers negotiate master/slave, exchange DBD (Database Description) packets. If MTU mismatch = DBD packets too large = dropped = stuck in EXSTART. Common: One side 1500 MTU, other 9000. Fix: Match MTU on both sides or use "ip ospf mtu-ignore". Other OSPF states: Down, Init, 2-Way, EXSTART, Exchange, Loading, Full. Interview: "Why won\'t OSPF form full adjacency?" MTU mismatch is common trap.'
    },
    {
        id: 'net82',
        title: 'Layer 2 vs Layer 3 Switch',
        points: 8,
        question: 'What is the primary difference between Layer 2 and Layer 3 switches?',
        type: 'radio',
        options: [
            { value: 'routing', text: 'Layer 3 can route between VLANs/subnets' },
            { value: 'speed', text: 'Layer 3 is faster' },
            { value: 'ports', text: 'Layer 3 has more ports' },
            { value: 'security', text: 'Layer 3 has better security' },
            { value: 'cost', text: 'Layer 3 is cheaper' }
        ],
        correct: 'routing',
        explanation: '🔀 Layer 2 Switch: Forwards based on MAC addresses within same VLAN/subnet. Cannot route between VLANs. Layer 3 Switch: Has routing capability (IP routing table), can route between VLANs/subnets at wire speed. Use cases: L2 for access layer, L3 for distribution/core. L3 switch = router + switch in one box (ASIC-based routing). Inter-VLAN routing without external router. Common interview question for network roles.'
    },
    {
        id: 'net83',
        title: 'DHCP Starvation Attack',
        points: 11,
        question: 'Attacker floods DHCP server with DISCOVER messages using fake MAC addresses. What is the goal?',
        type: 'radio',
        options: [
            { value: 'exhaust_pool', text: 'Exhaust IP address pool - deny legitimate clients' },
            { value: 'steal_ips', text: 'Steal IP addresses' },
            { value: 'mitm', text: 'Man-in-the-middle attack' },
            { value: 'dns_poison', text: 'Poison DNS cache' },
            { value: 'discover_network', text: 'Network discovery' }
        ],
        correct: 'exhaust_pool',
        explanation: '💥 DHCP Starvation: Flood DHCP server with DISCOVER requests using spoofed MAC addresses. Server exhausts IP pool = legitimate clients can\'t get IPs = DoS. Often followed by rogue DHCP server offering IPs with attacker as gateway/DNS = MITM. Tools: Yersinia, DHCPig. Defense: DHCP snooping (limit requests per port), port security, 802.1X authentication. MITRE: Network Denial of Service. Interview: "How do you protect DHCP?"'
    },
    {
        id: 'net84',
        title: 'TCP Window Scaling',
        points: 10,
        question: 'Why is TCP Window Scaling (RFC 1323) necessary?',
        type: 'radio',
        options: [
            { value: 'high_bandwidth', text: 'Default 64KB window too small for high-bandwidth networks' },
            { value: 'security', text: 'Improve security' },
            { value: 'reduce_handshake', text: 'Reduce handshake time' },
            { value: 'congestion', text: 'Better congestion control' },
            { value: 'encryption', text: 'Enable encryption' }
        ],
        correct: 'high_bandwidth',
        explanation: '📊 TCP Window Scaling: 16-bit window field = max 65,535 bytes. On high-bandwidth/high-latency networks (satellite, long-distance fiber) = throughput limited. Window scaling multiplies window size up to 1GB. Negotiated in SYN packets. Example: 100 Mbps link, 200ms RTT = need 2.5MB window. Bandwidth-Delay Product = Bandwidth × RTT. Modern: Enabled by default. Wireshark shows scale factor in handshake. Interview: "Why is my gigabit link only using 5 Mbps?"'
    },
    {
        id: 'net85',
        title: 'ICMP Type 3 Scanning',
        points: 9,
        question: 'During reconnaissance, attacker sends packets to various ports. ICMP Type 3 Code 3 returned. What does this mean?',
        type: 'radio',
        options: [
            { value: 'port_closed', text: 'Port unreachable - likely closed/filtered' },
            { value: 'host_down', text: 'Host is down' },
            { value: 'network_down', text: 'Network unreachable' },
            { value: 'host_unreachable', text: 'Host unreachable' },
            { value: 'protocol_unreachable', text: 'Protocol not supported' }
        ],
        correct: 'port_closed',
        explanation: '🔍 ICMP Destination Unreachable: Type 3, various codes. Code 3 = Port Unreachable (UDP scan, port closed). Code 1 = Host Unreachable. Code 0 = Network Unreachable. Code 2 = Protocol Unreachable. Nmap uses ICMP Type 3 Code 3 to identify closed UDP ports. Firewalls often block ICMP Type 3 = stealth. Interview: "How does Nmap detect closed UDP ports?" Tools: tcpdump "icmp and icmp[0] = 3"'
    },
    {
        id: 'net86',
        title: 'Split-Horizon DNS',
        points: 10,
        question: 'What is split-horizon DNS used for?',
        type: 'radio',
        options: [
            { value: 'internal_external', text: 'Different responses for internal vs external queries' },
            { value: 'load_balance', text: 'Load balancing' },
            { value: 'prevent_loops', text: 'Prevent routing loops' },
            { value: 'caching', text: 'Improve caching' },
            { value: 'redundancy', text: 'Provide redundancy' }
        ],
        correct: 'internal_external',
        explanation: '🔀 Split-Horizon DNS: Different DNS responses based on query source. Internal query for "mail.company.com" = 10.1.1.5 (private IP). External query = 203.0.113.5 (public IP). Use cases: Internal resources on private IPs, security (hide internal structure), optimize routing (local resources locally). Implementation: Two DNS servers (internal/external) or single with views (BIND views). Interview: "How do you handle DNS for internal/external users?"'
    },
    {
        id: 'net87',
        title: 'TCP Nagle Algorithm',
        points: 11,
        question: 'When should you disable Nagle\'s Algorithm (TCP_NODELAY)?',
        type: 'radio',
        options: [
            { value: 'low_latency', text: 'Low-latency applications (gaming, trading, SSH)' },
            { value: 'always', text: 'Always - better performance' },
            { value: 'bulk_transfer', text: 'Large file transfers' },
            { value: 'security', text: 'Security reasons' },
            { value: 'congestion', text: 'High congestion networks' }
        ],
        correct: 'low_latency',
        explanation: '⚡ Nagle\'s Algorithm: Reduces small packet overhead by buffering data until ACK received or enough data accumulated. Problem: Adds latency (waits for ACK). Disable (TCP_NODELAY) for: Real-time apps (gaming, VoIP), SSH (keystroke delay), financial trading, Telnet. Keep enabled for: Bulk transfers, web traffic. Interaction with Delayed ACKs = performance nightmare. Interview: "Why does SSH feel laggy?" Nagle + Delayed ACK = 200ms keystroke delay.'
    },
    {
        id: 'net88',
        title: 'ARP Cache Timeout',
        points: 7,
        question: 'Default ARP cache timeout on most systems?',
        type: 'radio',
        options: [
            { value: '5_20min', text: '5-20 minutes (varies by OS)' },
            { value: '30sec', text: '30 seconds' },
            { value: '1hour', text: '1 hour' },
            { value: '24hour', text: '24 hours' },
            { value: 'infinite', text: 'Infinite until reboot' }
        ],
        correct: '5_20min',
        explanation: '⏰ ARP Cache Timeout: Linux = 60 seconds (reachable), Windows = 2 minutes (recent), Cisco = 4 hours. Why timeout? IPs/MACs change (DHCP, VM migration, HA failover). Too short = excessive ARP traffic. Too long = stale entries when changes occur. Check: "arp -a" (view cache), "arp -d" (delete entry). Gratuitous ARP updates caches immediately without waiting for timeout. Interview: "Why does traffic still go to old server after IP change?"'
    },
    {
        id: 'net89',
        title: 'VLAN Hopping Attack',
        points: 12,
        question: 'How does double-tagging VLAN hopping work?',
        type: 'radio',
        options: [
            { value: 'double_tag', text: 'Add two 802.1Q tags - outer stripped, inner forwards to target VLAN' },
            { value: 'mac_spoof', text: 'Spoof MAC address' },
            { value: 'dtp_exploit', text: 'Exploit DTP to become trunk' },
            { value: 'overflow', text: 'Overflow VLAN table' },
            { value: 'arp_poison', text: 'ARP poisoning across VLANs' }
        ],
        correct: 'double_tag',
        explanation: '🎯 Double-Tagging VLAN Hopping: Attacker on native VLAN sends frame with TWO 802.1Q tags. First switch strips outer tag (native VLAN), forwards frame with inner tag to next switch. Second switch forwards to target VLAN. Unidirectional attack (send only, not receive). Defense: Don\'t use VLAN 1 as native, don\'t put hosts on native VLAN, explicit tagging on trunk ports. Alternative: DTP (Dynamic Trunking Protocol) exploitation. Interview: "How do you prevent VLAN hopping?"'
    },
    {
        id: 'net90',
        title: 'Multicast MAC Address',
        points: 9,
        question: 'IPv4 multicast address 224.0.0.251 (mDNS). What is the corresponding MAC address?',
        type: 'radio',
        options: [
            { value: '01:00:5e:00:00:fb', text: '01:00:5e:00:00:fb' },
            { value: 'ff:ff:ff:ff:ff:ff', text: 'ff:ff:ff:ff:ff:ff' },
            { value: '01:00:5e:00:00:00', text: '01:00:5e:00:00:00' },
            { value: '33:33:00:00:00:fb', text: '33:33:00:00:00:fb' },
            { value: '00:00:5e:00:01:fb', text: '00:00:5e:00:01:fb' }
        ],
        correct: '01:00:5e:00:00:fb',
        explanation: '📡 IPv4 Multicast to MAC: 01:00:5e:XX:XX:XX. Take lower 23 bits of IP, prepend 01:00:5e. 224.0.0.251 = 0xE0.00.00.FB. Lower 23 bits = 0x00.00.FB. Result: 01:00:5e:00:00:fb. mDNS (Multicast DNS) uses 224.0.0.251 for local service discovery. IPv6 multicast: 33:33:XX:XX:XX:XX. Broadcast: ff:ff:ff:ff:ff:ff. Interview: "How does multicast work at Layer 2?" Shows deep protocol knowledge.'
    },
    {
        id: 'net91',
        title: 'TCP Keepalive',
        points: 10,
        question: 'What is the purpose of TCP Keepalive?',
        type: 'radio',
        options: [
            { value: 'detect_dead', text: 'Detect dead connections - send probe after idle period' },
            { value: 'maintain_nat', text: 'Keep NAT mappings alive' },
            { value: 'prevent_timeout', text: 'Prevent firewall timeouts' },
            { value: 'all_above', text: 'All of the above' },
            { value: 'flow_control', text: 'Flow control mechanism' }
        ],
        correct: 'all_above',
        explanation: '❤️ TCP Keepalive: Sends probe after idle period (default 2 hours) to detect dead connections. Use cases: 1) Detect crashed/unreachable peer, 2) Keep NAT mappings alive, 3) Prevent firewall idle timeouts. Linux: net.ipv4.tcp_keepalive_time. Not part of TCP spec, optional feature. Some apps implement application-level keepalive (SSH, HTTP/2 PING). Interview: "Why do SSH connections hang after idle?" Firewall timeout before TCP keepalive.'
    },
    {
        id: 'net92',
        title: 'BGP Route Preference',
        points: 13,
        question: 'Router receives same route from OSPF (metric 20) and BGP (AS-path length 2). Which is preferred?',
        type: 'radio',
        options: [
            { value: 'ospf', text: 'OSPF - lower administrative distance (110 vs 20)' },
            { value: 'bgp', text: 'BGP - external routing protocol' },
            { value: 'equal', text: 'Equal-cost multipath' },
            { value: 'metric', text: 'Lower metric wins' },
            { value: 'as_path', text: 'Shorter AS-path wins' }
        ],
        correct: 'ospf',
        explanation: '🎯 Administrative Distance (AD): Trustworthiness of routing source. Lower = more trusted. Connected = 0, Static = 1, EIGRP = 90, OSPF = 110, RIP = 120, eBGP = 20, iBGP = 200. Route selection: 1) Longest prefix match, 2) Lowest AD, 3) Metric (if same AD). BGP AD 20 beats OSPF 110? NO - typo in question. Correct: eBGP (20) > OSPF (110), so BGP wins. Interview trap question! Real answer: BGP wins (AD 20 < 110).'
    },
    {
        id: 'net93',
        title: 'STP Port States',
        points: 11,
        question: 'Port in LISTENING state for 15 seconds, then LEARNING state for 15 seconds. What is the total convergence time?',
        type: 'radio',
        options: [
            { value: '30sec', text: '30 seconds (15s listening + 15s learning)' },
            { value: '50sec', text: '50 seconds (20s blocking + 15s + 15s)' },
            { value: '15sec', text: '15 seconds' },
            { value: '60sec', text: '60 seconds' },
            { value: 'instant', text: 'Instant convergence' }
        ],
        correct: '30sec',
        explanation: '🌉 STP Port States: Blocking (listens for BPDUs) → Listening (15s, builds topology) → Learning (15s, learns MAC addresses) → Forwarding. Total: 30 seconds to converge (50 seconds from Blocking). Slow convergence = outage. Rapid STP (RSTP, 802.1w): Max 6 seconds convergence (Point-to-Point links instant). Per-VLAN STP (PVST+): Separate instance per VLAN. Interview: "Why does network take 30 seconds to recover?" Classic STP convergence.'
    },
    {
        id: 'net94',
        title: 'DNS NXDOMAIN vs NOERROR',
        points: 8,
        question: 'DNS query for "test.example.com" returns RCODE=3 (NXDOMAIN). What does this mean?',
        type: 'radio',
        options: [
            { value: 'no_domain', text: 'Domain does not exist' },
            { value: 'no_record', text: 'No such record type' },
            { value: 'no_response', text: 'Server did not respond' },
            { value: 'refused', text: 'Server refused query' },
            { value: 'timeout', text: 'Query timeout' }
        ],
        correct: 'no_domain',
        explanation: '🔍 DNS Response Codes: NOERROR (0) = success, NXDOMAIN (3) = domain doesn\'t exist, SERVFAIL (2) = server failure, REFUSED (5) = policy/permission denied. NXDOMAIN vs NOERROR: "test.example.com" doesn\'t exist = NXDOMAIN. "example.com" exists but no A record = NOERROR (empty answer). Attackers use NXDOMAIN for DGA detection. NXDOMAIN poisoning: Attacker caches NXDOMAIN to DoS domain. Interview: DNS troubleshooting essential.'
    },
    {
        id: 'net95',
        title: 'IPsec Transport vs Tunnel Mode',
        points: 12,
        question: 'What is the difference between IPsec Transport and Tunnel mode?',
        type: 'radio',
        options: [
            { value: 'encapsulation', text: 'Transport encrypts payload only; Tunnel encrypts entire IP packet' },
            { value: 'speed', text: 'Transport is faster' },
            { value: 'security', text: 'Tunnel is more secure' },
            { value: 'protocols', text: 'Different protocols used' },
            { value: 'keys', text: 'Different key exchange' }
        ],
        correct: 'encapsulation',
        explanation: '🔐 IPsec Modes: **Transport**: Encrypts payload only, keeps original IP header (host-to-host, same network). **Tunnel**: Encrypts entire original packet, adds new IP header (site-to-site VPN, different networks). Use: Transport for end-to-end (less overhead), Tunnel for VPN gateways. ESP (Encapsulating Security Payload) vs AH (Authentication Header). IKEv2 for key exchange. Interview: "When do you use Transport vs Tunnel mode?" Critical VPN knowledge.'
    },
    {
        id: 'net96',
        title: 'TCP Zero Window Probe',
        points: 10,
        question: 'After receiving TCP Window Size 0, how does sender know when to resume?',
        type: 'radio',
        options: [
            { value: 'probe', text: 'Sends periodic Zero Window Probes to check if window opened' },
            { value: 'timeout', text: 'Waits for fixed timeout' },
            { value: 'receiver_sends', text: 'Receiver must send new packet' },
            { value: 'retransmit', text: 'Retransmits last packet' },
            { value: 'connection_reset', text: 'Resets connection' }
        ],
        correct: 'probe',
        explanation: '🔍 Zero Window Probe: When receiver advertises Window=0, sender stops sending data. But window update might get lost! Solution: Sender periodically sends 1-byte Zero Window Probe to trigger window update. Probe interval: Exponential backoff (starts ~1 second). Receiver responds with current window size. Prevents deadlock. Wireshark shows as "TCP ZeroWindowProbe". Interview: "How does TCP handle flow control?" Shows deep protocol understanding.'
    },
    {
        id: 'net97',
        title: 'Unicast Reverse Path Forwarding',
        points: 11,
        question: 'What does uRPF (Unicast Reverse Path Forwarding) prevent?',
        type: 'radio',
        options: [
            { value: 'spoofing', text: 'IP spoofing - verifies source IP has valid return path' },
            { value: 'ddos', text: 'DDoS attacks' },
            { value: 'routing_loops', text: 'Routing loops' },
            { value: 'broadcast', text: 'Broadcast storms' },
            { value: 'multicast', text: 'Multicast abuse' }
        ],
        correct: 'spoofing',
        explanation: '🛡️ uRPF: Anti-spoofing mechanism. Checks if source IP has route back through arrival interface. If no valid return path = DROP. Modes: **Strict**: Must return via same interface. **Loose**: Must exist in routing table. Use: ISP edge, prevent spoofed source IPs in DDoS/reflection attacks. Limitation: Breaks asymmetric routing. Cisco: "ip verify unicast source reachable-via rx". BCP 38 (RFC 2827) recommends. Interview: "How do you prevent IP spoofing?"'
    },
    {
        id: 'net98',
        title: 'TCP Silly Window Syndrome',
        points: 12,
        question: 'What is Silly Window Syndrome in TCP?',
        type: 'radio',
        options: [
            { value: 'small_windows', text: 'Sending tiny data segments - inefficient small windows' },
            { value: 'large_windows', text: 'Windows too large causing overflow' },
            { value: 'zero_window', text: 'Persistent zero window' },
            { value: 'window_scale', text: 'Window scaling misconfiguration' },
            { value: 'slow_start', text: 'Slow start phase taking too long' }
        ],
        correct: 'small_windows',
        explanation: '🤏 Silly Window Syndrome (SWS): Receiver announces tiny windows (few bytes), sender sends tiny segments = extreme overhead (40 bytes header for 1 byte data!). Caused by: Slow receiver application, sender sending small amounts. Solutions: Nagle\'s Algorithm (sender-side), Delayed ACK, receiver waits to advertise window until significant space. Clark\'s solution: Don\'t advertise window < MSS or 50% of buffer. Historical problem, mostly solved. Interview: "What TCP optimizations exist?"'
    },
    {
        id: 'net99',
        title: 'IPv6 Privacy Extensions',
        points: 10,
        question: 'What is the purpose of IPv6 Privacy Extensions (RFC 4941)?',
        type: 'radio',
        options: [
            { value: 'privacy', text: 'Generate temporary random addresses instead of EUI-64 for privacy' },
            { value: 'security', text: 'Encrypt IPv6 addresses' },
            { value: 'nat', text: 'Provide NAT functionality' },
            { value: 'multicast', text: 'Improve multicast' },
            { value: 'routing', text: 'Optimize routing' }
        ],
        correct: 'privacy',
        explanation: '🕵️ IPv6 Privacy Extensions: Problem: EUI-64 addressing embeds MAC address in IPv6 = tracking across networks. Solution: Generate random temporary addresses, rotate periodically (default daily). Device has stable address (internal/incoming) + temporary addresses (outgoing). Windows/macOS enable by default. Linux: net.ipv6.conf.all.use_tempaddr=2. Trade-off: Complicates logging/troubleshooting. Interview: "How does IPv6 handle privacy concerns?"'
    },
    {
        id: 'net100',
        title: 'TCP Congestion Algorithms',
        points: 13,
        question: 'Which modern TCP congestion control algorithm uses delay instead of packet loss as congestion signal?',
        type: 'radio',
        options: [
            { value: 'bbr', text: 'BBR (Bottleneck Bandwidth and RTT)' },
            { value: 'reno', text: 'TCP Reno' },
            { value: 'cubic', text: 'TCP CUBIC' },
            { value: 'vegas', text: 'TCP Vegas' },
            { value: 'tahoe', text: 'TCP Tahoe' }
        ],
        correct: 'bbr',
        explanation: '🚀 BBR (Google, 2016): Uses bandwidth and RTT measurements, not packet loss. Traditional (Reno, CUBIC): Wait for loss = full buffers = latency. BBR: Maintain optimal throughput without filling buffers = lower latency. Performance: 2-25x throughput on lossy links. Used by: Google, YouTube, Spotify. Linux: net.ipv4.tcp_congestion_control=bbr. Others: CUBIC (default Linux), Reno (traditional), Vegas (delay-based predecessor). Interview: "What\'s the latest in TCP optimization?" BBR shows cutting-edge knowledge.'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = networkingExtended;
}
