/**
 * Extended Ports & Protocols Questions (port51-100)
 * Lazy-loaded when user clicks "Load More Questions"
 *
 * Current Status: port51-60 complete (10 questions)
 * Base questions (port1-50) are in questions_data.js
 */

const portsExtended = [
    {
        id: 'port51',
        title: 'MQTT Protocol Security',
        points: 10,
        question: 'IoT devices communicate using MQTT (port 1883). What is the primary security concern?',
        type: 'radio',
        options: [
            { value: 'plaintext', text: 'Unencrypted by default - credentials and data in cleartext' },
            { value: 'dos', text: 'Vulnerable to DDoS only' },
            { value: 'slow', text: 'Too slow for real-time communication' },
            { value: 'expensive', text: 'Expensive licensing costs' },
            { value: 'incompatible', text: 'Not compatible with IoT devices' }
        ],
        correct: 'plaintext',
        explanation: '📡 MQTT (Message Queue Telemetry Transport): Lightweight pub/sub protocol for IoT. Port 1883 (unencrypted), 8883 (TLS). Security issues: 1) **No encryption by default**: Credentials, sensor data in plaintext, 2) **Weak authentication**: Often default/no passwords, 3) **Open brokers**: Publicly accessible (Shodan finds thousands). Attack: Eavesdrop on smart home, manipulate industrial sensors. Defense: MQTT over TLS (port 8883), strong auth, firewall rules, VPN. Used by: AWS IoT, Azure IoT Hub. Interview: "IoT protocol security."'
    },
    {
        id: 'port52',
        title: 'RDP Protocol Attacks',
        points: 12,
        question: 'Attackers scan for Remote Desktop Protocol (RDP) and launch brute force attacks. Which ports are targeted? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'tcp3389', text: 'TCP 3389 - default RDP port' },
            { value: 'udp3389', text: 'UDP 3389 - RDP over UDP' },
            { value: 'tcp443', text: 'TCP 443 - RDP over HTTPS gateway' },
            { value: 'tcp22', text: 'TCP 22 - SSH (not RDP)' },
            { value: 'tcp80', text: 'TCP 80 - HTTP (not RDP)' }
        ],
        correct: ['tcp3389', 'udp3389', 'tcp443'],
        explanation: '🖥️ RDP Ports: **TCP 3389** = classic RDP. **UDP 3389** = RDP 8.0+ for better performance (UDP Transport). **TCP 443** = RDP Gateway (HTTPS tunnel for external access). Attacks: 1) **Brute force**: Try default/weak passwords (admin/password), 2) **BlueKeep** (CVE-2019-0708): Pre-auth RCE on unpatched Windows, 3) **Man-in-the-middle**: Downgrade encryption. Defense: MFA, VPN-only access, disable RDP on internet, Network Level Authentication (NLA), rate limiting. Shodan query: port:3389. Interview: "RDP security hardening."'
    },
    {
        id: 'port53',
        title: 'DNS over HTTPS (DoH)',
        points: 11,
        question: 'Applications use DNS over HTTPS (DoH) on port 443. What is the security implication for corporate networks?',
        type: 'radio',
        options: [
            { value: 'bypass', text: 'Bypasses DNS filtering and monitoring (looks like HTTPS traffic)' },
            { value: 'faster', text: 'Just provides faster DNS resolution' },
            { value: 'cheaper', text: 'Reduces bandwidth costs' },
            { value: 'more_secure', text: 'Only provides more security (no downside)' },
            { value: 'slower', text: 'Significantly slower performance' }
        ],
        correct: 'bypass',
        explanation: '🔒 DoH Security Trade-off: **Privacy benefit**: Encrypts DNS queries (ISP can\'t see). **Corporate concern**: Bypasses DNS-based security controls (DNS firewall, malicious domain blocking, DLP). Traffic looks like normal HTTPS to port 443 = can\'t inspect/block at network layer. Browsers: Firefox, Chrome support DoH. Enterprise response: 1) Block DoH servers (dns.google, cloudflare-dns.com), 2) Configure browsers via GPO to use internal DNS, 3) TLS inspection (controversial). Similar: DNS over TLS (port 853). Interview: "DoH impact on enterprise security."'
    },
    {
        id: 'port54',
        title: 'Memcached Amplification Attack',
        points: 13,
        question: 'Attacker sends small UDP packet to Memcached server (port 11211). Server responds with massive payload to victim. What attack is this?',
        type: 'radio',
        options: [
            { value: 'amplification', text: 'DDoS amplification attack (reflection)' },
            { value: 'mitm', text: 'Man-in-the-middle attack' },
            { value: 'cache_poison', text: 'Cache poisoning' },
            { value: 'buffer', text: 'Buffer overflow' },
            { value: 'injection', text: 'SQL injection' }
        ],
        correct: 'amplification',
        explanation: '💥 Memcached Amplification: UDP-based DDoS. Attack: 1) Send spoofed UDP request (victim\'s IP as source) to open Memcached server, 2) Request small (15 bytes), 3) Response massive (up to 50000x amplification!), 4) Victim overwhelmed. Famous: GitHub DDoS (1.35 Tbps, 2018). Defense: **Never expose Memcached to internet** (bind to localhost), UDP blocked, rate limiting. Other amplification: NTP (port 123), DNS (port 53), SSDP (port 1900). Shodan query: port:11211. Interview: "DDoS amplification attack types."'
    },
    {
        id: 'port55',
        title: 'SMB Port Security',
        points: 11,
        question: 'Security team blocks SMB ports 445 and 139 at internet firewall. What attacks does this prevent?',
        type: 'checkbox',
        options: [
            { value: 'wannacry', text: 'WannaCry and EternalBlue ransomware' },
            { value: 'enum', text: 'Network enumeration and share discovery' },
            { value: 'lateral', text: 'Lateral movement from internet' },
            { value: 'relay', text: 'SMB relay attacks from external attackers' },
            { value: 'all_smb', text: 'Blocks ALL SMB attacks everywhere' }
        ],
        correct: ['wannacry', 'enum', 'lateral', 'relay'],
        explanation: '🚫 SMB Security: Port 445 (SMB over TCP), Port 139 (SMB over NetBIOS). Attacks: **EternalBlue** (CVE-2017-0144): RCE on unpatched Windows, used by WannaCry/NotPetya. **SMB relay**: Steal NTLM hashes. **Enumeration**: List shares, users. **Lateral movement**: Pivot between internal hosts. Defense: 1) **Block at perimeter** (SMB should NEVER be internet-facing), 2) **Internal**: SMB signing (prevents relay), disable SMBv1, patch. Blocking at firewall only stops external attacks, not internal propagation. Interview: "SMB attack vectors and mitigations."'
    },
    {
        id: 'port56',
        title: 'Elasticsearch Exposure',
        points: 12,
        question: 'Shodan shows company Elasticsearch instance on port 9200 exposed to internet without authentication. What is the risk?',
        type: 'checkbox',
        options: [
            { value: 'data_leak', text: 'Complete data exposure - anyone can read all indexed data' },
            { value: 'modify', text: 'Attackers can modify/delete data' },
            { value: 'rce', text: 'Remote code execution via Groovy scripts' },
            { value: 'ransomware', text: 'Database ransomware (delete data, demand payment)' },
            { value: 'safe', text: 'Actually safe - Elasticsearch has built-in security' }
        ],
        correct: ['data_leak', 'modify', 'rce', 'ransomware'],
        explanation: '💀 Elasticsearch Exposure: Default config = no authentication, exposes REST API on port 9200. Risks: 1) **Data breach**: curl http://victim:9200/_search?pretty = dump all data, 2) **Modification**: Delete indices, corrupt data, 3) **RCE**: Groovy scripts, CVE-2014-3120 and others, 4) **Ransomware**: Automated bots delete DB, leave ransom note. Famous: Multiple healthcare breaches, MongoDB/Elasticsearch ransomware campaigns. Defense: Authentication (X-Pack Security), VPN-only access, firewall rules. Shodan query: port:9200. Interview: "Database security hardening."'
    },
    {
        id: 'port57',
        title: 'SSDP Amplification',
        points: 10,
        question: 'UDP port 1900 (SSDP) used for UPnP device discovery. How is it abused for DDoS?',
        type: 'radio',
        options: [
            { value: 'amplification', text: 'Amplification attack - small request, large response to victim' },
            { value: 'discovery', text: 'Just device discovery (not DDoS)' },
            { value: 'mitm', text: 'Man-in-the-middle attack only' },
            { value: 'injection', text: 'Code injection attack' },
            { value: 'safe', text: 'Cannot be used for DDoS' }
        ],
        correct: 'amplification',
        explanation: '📡 SSDP/UPnP Abuse: Simple Service Discovery Protocol (UDP 1900) for home routers, smart TVs, printers. Amplification attack: 1) Spoofed M-SEARCH request (victim source IP), 2) Devices respond with service descriptions (30x amplification), 3) Victim flooded. Also: UPnP port mapping abuse (open firewall ports remotely). Defense: Disable UPnP on routers, firewall blocks UDP 1900 from internet, rate limiting. Similar to DNS/NTP/Memcached amplification. Shodan finds millions of exposed UPnP devices. Interview: "UPnP security risks."'
    },
    {
        id: 'port58',
        title: 'MongoDB Default Port',
        points: 9,
        question: 'MongoDB exposed on default port 27017 without authentication. What commands can attacker run? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'read', text: 'Read all databases and collections' },
            { value: 'write', text: 'Insert, update, delete data' },
            { value: 'drop', text: 'Drop databases' },
            { value: 'admin', text: 'Create admin users' },
            { value: 'nothing', text: 'Nothing - MongoDB enforces auth by default' }
        ],
        correct: ['read', 'write', 'drop', 'admin'],
        explanation: '🍃 MongoDB Exposure: Old versions default to no authentication. Attackers can: db.collection.find(), insertOne(), deleteMany(), db.dropDatabase(), db.createUser(). Famous: 2017 MongoDB ransomware epidemic (thousands of unprotected DBs deleted). Modern: MongoDB 3.6+ requires auth but many old instances exposed. Defense: Enable authentication, bind to localhost (bindIp: 127.0.0.1), firewall rules, update to latest version. Shodan: port:27017. Interview: "NoSQL database security."'
    },
    {
        id: 'port59',
        title: 'VNC Protocol Security',
        points: 11,
        question: 'VNC (Virtual Network Computing) discovered on port 5900 with weak password. What can attacker do?',
        type: 'radio',
        options: [
            { value: 'full_control', text: 'Complete remote desktop access - view screen, control keyboard/mouse' },
            { value: 'view_only', text: 'View screen only (no control)' },
            { value: 'file_transfer', text: 'File transfer only' },
            { value: 'port_scan', text: 'Use as port scanning pivot' },
            { value: 'limited', text: 'Very limited access' }
        ],
        correct: 'full_control',
        explanation: '🖱️ VNC Security: Remote desktop protocol, port 5900+ (5900, 5901, 5902 for multiple sessions). Weak security: 1) **Weak auth**: Max 8-character password (DES encryption), brute-forceable, 2) **No encryption**: Keystrokes/screen in cleartext (VNC over SSH/VPN needed), 3) **Many have no password**. Attack: Brute force password, gain full desktop control = install malware, steal data, lateral movement. Defense: VNC over SSH tunnel, strong password, VPN-only access, better alternative (RDP with MFA). Shodan: hundreds of thousands exposed. Interview: "Remote access security."'
    },
    {
        id: 'port60',
        title: 'AMQP Protocol Usage',
        points: 10,
        question: 'Enterprise uses AMQP (port 5672) for RabbitMQ message broker. What is a security best practice?',
        type: 'radio',
        options: [
            { value: 'tls', text: 'Use AMQPS (port 5671) with TLS encryption and authentication' },
            { value: 'port_change', text: 'Just change to non-standard port' },
            { value: 'no_auth', text: 'Disable authentication for performance' },
            { value: 'public', text: 'Expose to internet for external integration' },
            { value: 'udp', text: 'Switch to UDP for better performance' }
        ],
        correct: 'tls',
        explanation: '📨 AMQP Security: Advanced Message Queuing Protocol, used by RabbitMQ, Azure Service Bus. Port 5672 (plaintext), 5671 (TLS). Risks: 1) **Message interception**: Credentials, sensitive data in plaintext, 2) **Weak auth**: Default guest/guest credentials, 3) **Message injection**: Attacker sends malicious messages. Defense: **AMQPS (TLS)**, strong authentication, message encryption, network segmentation, remove default accounts. Management UI (port 15672) often exposed with default creds. Interview: "Message queue security."'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = portsExtended;
}
