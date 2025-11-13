/**
 * Extended Ports & Protocols Questions (port51-70)
 * Advanced SOC Analyst training - Deep protocol analysis
 * Lazy-loaded when user clicks "Load More Questions"
 */

const portsExtended = [
    {
        id: 'port51',
        title: 'IPMI Remote Management Exploitation',
        points: 8,
        question: 'IPMI (Intelligent Platform Management Interface) runs on port 623. What critical vulnerability affects it?',
        type: 'radio',
        options: [
            { value: 'cipher_zero', text: 'Cipher Zero authentication bypass (CVE-2013-4786)' },
            { value: 'encryption_weak', text: 'Weak SSL encryption only' },
            { value: 'ddos', text: 'DDoS amplification vector' },
            { value: 'safe', text: 'IPMI v2.0 is secure by design' }
        ],
        correct: 'cipher_zero',
        mitre: 'T1190',
        explanation: '🔧 Port 623 (UDP) = IPMI - out-of-band management for servers (Dell iDRAC, HP iLO, Supermicro). **Cipher Zero Attack (CVE-2013-4786)**: Request authentication with cipher suite 0 → BMC responds with password hash → crack offline (MD5/SHA1) → full server control (power cycles, console access, firmware modification). Additional risks: Default passwords (ADMIN/ADMIN), RAKP authentication hash disclosure, pre-boot environment access. Defense: 1) **Disable Cipher Zero**, 2) **Isolate management network** (dedicated VLAN), 3) **Strong unique passwords**, 4) **Firmware updates**, 5) **Network ACLs**. Metasploit module: `auxiliary/scanner/ipmi/ipmi_dumphashes`. MITRE: T1190.'
    },
    {
        id: 'port52',
        title: 'HTTP/3 and QUIC Protocol',
        points: 7,
        question: 'HTTP/3 uses UDP port 443 (QUIC protocol). What security monitoring challenges does this present?',
        type: 'checkbox',
        options: [
            { value: 'inspection', text: 'Traditional DPI cannot inspect encrypted QUIC packets' },
            { value: 'fingerprint', text: 'Difficult to fingerprint applications and detect C2' },
            { value: 'bypass', text: 'UDP allows bypassing TCP-only security controls' },
            { value: 'none', text: 'HTTP/3 is easier to monitor than HTTP/2' }
        ],
        correct: ['inspection', 'fingerprint', 'bypass'],
        mitre: 'T1071.001',
        explanation: '🚀 HTTP/3 = HTTP over QUIC (UDP 443). Google/Cloudflare adoption growing. Security challenges: 1) **Encrypted by default** - TLS 1.3 integrated, hard to inspect without MITM, 2) **UDP-based** - bypasses TCP firewalls, stateful inspection, 3) **Connection migration** - IP changes mid-session (NAT rebinding attacks), 4) **Fast handshake** - 0-RTT can replay attacks, 5) **Protocol confusion** - tools see UDP 443, miss HTTP traffic. Malware using QUIC for C2 (harder detection). Defense: 1) **QUIC-aware firewalls/IDS**, 2) **TLS interception with QUIC support**, 3) **Monitor connection patterns** (frequency, volume), 4) **Block UDP 443** if not needed, 5) **Endpoint detection**. MITRE: T1071.001.'
    },
    {
        id: 'port53',
        title: 'gRPC Protocol Security',
        points: 7,
        question: 'gRPC services typically run on custom ports using HTTP/2. What unique security considerations exist?',
        type: 'checkbox',
        options: [
            { value: 'reflection', text: 'Server reflection API exposes all available methods' },
            { value: 'deserialization', text: 'Protobuf deserialization vulnerabilities' },
            { value: 'auth', text: 'No authentication by default - must implement custom' },
            { value: 'encrypted', text: 'gRPC enforces authentication and encryption by default' }
        ],
        correct: ['reflection', 'deserialization', 'auth'],
        mitre: 'T1190',
        explanation: '⚡ gRPC = Google RPC framework (HTTP/2 + Protocol Buffers). Common ports: random high ports or 50051 (convention). Security issues: 1) **Server Reflection** - `grpcurl -plaintext server:50051 list` exposes all services/methods (reconnaissance), 2) **No auth by default** - must implement interceptors/middleware, 3) **Protobuf deserialization** - malformed messages cause DoS or memory corruption, 4) **Metadata injection** - similar to HTTP header injection, 5) **TLS optional** - many dev environments use plaintext. Attack: Enumerate methods → call sensitive RPCs → extract data. Defense: 1) **Disable reflection in prod**, 2) **Implement auth** (JWT, mTLS), 3) **Input validation**, 4) **Always use TLS**, 5) **Rate limiting**. Tools: grpcurl, grpcox. MITRE: T1190.'
    },
    {
        id: 'port54',
        title: 'etcd Key-Value Store',
        points: 8,
        question: 'etcd (Kubernetes datastore) exposes client API on port 2379 without authentication. What is compromised?',
        type: 'radio',
        options: [
            { value: 'cluster', text: 'Entire Kubernetes cluster including all secrets' },
            { value: 'metadata', text: 'Only pod metadata, no sensitive data' },
            { value: 'logs', text: 'Application logs only' },
            { value: 'safe', text: 'etcd has read-only mode for external access' }
        ],
        correct: 'cluster',
        mitre: 'T1552.007',
        explanation: '🔐 Port 2379 = etcd client API, 2380 = peer communication. etcd stores **entire Kubernetes state**: all secrets (API tokens, passwords, TLS certs), ConfigMaps, pod specs, RBAC policies. Unauthenticated access = **game over**: 1) `etcdctl get / --prefix` dumps ALL data, 2) Extract service account tokens → cluster-admin access, 3) **Modify cluster state** → inject malicious pods, 4) **Persistent backdoors**. Real incidents: Tesla cryptojacking (exposed etcd), multiple Kubernetes compromises. Defense: 1) **Client cert authentication** (--cert-file, --key-file), 2) **Firewall rules** (localhost/internal only), 3) **Encryption at rest** (--encryption-provider-config), 4) **RBAC for etcd access**, 5) **mTLS for peer communication**. MITRE: T1552.007 (Container API).'
    },
    {
        id: 'port55',
        title: 'DNS over HTTPS (DoH) Detection',
        points: 7,
        question: 'Users are bypassing DNS monitoring by using DoH to 1.1.1.1:443. How can you detect this?',
        type: 'checkbox',
        options: [
            { value: 'sni', text: 'Inspect TLS SNI for cloudflare-dns.com, dns.google' },
            { value: 'endpoints', text: 'Monitor connections to known DoH resolver IPs' },
            { value: 'patterns', text: 'Analyze traffic patterns (frequent small HTTPS requests)' },
            { value: 'impossible', text: 'DoH is impossible to detect due to encryption' }
        ],
        correct: ['sni', 'endpoints', 'patterns'],
        mitre: 'T1071.004',
        explanation: '🔒 DoH (DNS over HTTPS) - port 443. Privacy benefit: Encrypts DNS queries. Security problem: **Bypasses DNS-based security controls** (content filters, malware blocking, DLP, DNS logs). Detection methods: 1) **TLS SNI inspection** - look for cloudflare-dns.com, dns.google, dns.quad9.net (before encryption), 2) **Known DoH IPs** - block 1.1.1.1, 8.8.8.8, 9.9.9.9 if not authorized, 3) **Traffic patterns** - many small POST requests to /dns-query endpoint, 4) **User-Agent strings**, 5) **Endpoint monitoring** - DoH resolvers in browser configs. Malware using DoH for C2 domain resolution. Mitigation: 1) **Block DoH resolvers**, 2) **Enforce enterprise DNS** (GPO, MDM), 3) **TLS inspection**, 4) **Canary domains**. MITRE: T1071.004 (DNS - though over HTTPS).'
    },
    {
        id: 'port56',
        title: 'VXLAN Network Overlay',
        points: 8,
        question: 'VXLAN encapsulation uses UDP port 4789 for overlay networks. What security risks does this introduce?',
        type: 'checkbox',
        options: [
            { value: 'visibility', text: 'Loss of visibility into encapsulated traffic' },
            { value: 'evasion', text: 'Attackers can use VXLAN to evade security controls' },
            { value: 'mitm', text: 'VXLAN has no encryption - vulnerable to MITM' },
            { value: 'encrypted', text: 'VXLAN provides end-to-end encryption' }
        ],
        correct: ['visibility', 'evasion', 'mitm'],
        mitre: 'T1599',
        explanation: '🌐 Port 4789 (UDP) = VXLAN (Virtual Extensible LAN) - overlay networking (VMware NSX, Kubernetes CNI, cloud). Security challenges: 1) **No encryption by default** - VXLAN header + original frame in plaintext (wireshark sees inner traffic if on same network), 2) **Blind spot** - traditional firewalls/IDS see UDP 4789, can\'t inspect encapsulated payload, 3) **Lateral movement** - attackers create rogue VXLAN tunnels between compromised hosts, 4) **VTEP spoofing** - impersonate VXLAN Tunnel Endpoints, 5) **Amplification** - craft packets for reflection attacks. Defense: 1) **Encrypt overlay** (IPsec over VXLAN, WireGuard), 2) **VXLAN-aware security** (NSX DFW, Cilium), 3) **Restrict VTEP membership** (static configs, not multicast), 4) **Monitor VXLAN control plane**, 5) **Micro-segmentation**. Similar: Geneve (6081), GRE. MITRE: T1599 (Network Boundary Bridging).'
    },
    {
        id: 'port57',
        title: 'Container Registry Exposure',
        points: 7,
        question: 'Docker Registry V2 API on port 5000 is accessible without authentication. What can attackers do?',
        type: 'checkbox',
        options: [
            { value: 'pull', text: 'Pull all container images including proprietary code' },
            { value: 'push', text: 'Push malicious images with backdoors' },
            { value: 'secrets', text: 'Extract secrets embedded in image layers' },
            { value: 'readonly', text: 'Registry API is always read-only for security' }
        ],
        correct: ['pull', 'push', 'secrets'],
        mitre: 'T1552.007',
        explanation: '🐳 Port 5000 = Docker Registry (also 5001 with TLS). Unauthenticated registry = **supply chain compromise**: 1) **Pull images** - `curl http://registry:5000/v2/_catalog` lists all repos, download proprietary apps/code, 2) **Push malicious images** - inject cryptominers, backdoors → developers pull compromised images, 3) **Extract secrets** - dive/docker history reveals hardcoded API keys, passwords in layers, 4) **Tag manipulation** - replace "latest" tag with malicious version. Real attacks: Cryptojacking containers, supply chain poisoning. Defense: 1) **Enable authentication** (basic auth, token auth), 2) **TLS + client certs**, 3) **Image signing** (Docker Content Trust, Notary), 4) **Vulnerability scanning** (Trivy, Clair), 5) **Network isolation**, 6) **Read-only for most users**. Cloud: ECR, ACR, GCR have better default security. MITRE: T1552.007.'
    },
    {
        id: 'port58',
        title: 'BGP Hijacking Detection',
        points: 9,
        question: 'BGP (Border Gateway Protocol) uses TCP port 179. What indicators suggest BGP hijacking?',
        type: 'checkbox',
        options: [
            { value: 'routes', text: 'Unexpected route announcements for your IP space' },
            { value: 'asn', text: 'New ASN appearing in path to your prefixes' },
            { value: 'latency', text: 'Sudden latency increases or route path changes' },
            { value: 'encrypted', text: 'BGP encryption prevents hijacking' }
        ],
        correct: ['routes', 'asn', 'latency'],
        mitre: 'T1590.001',
        explanation: '🌍 Port 179 (TCP) = BGP. **BGP Hijacking**: Attacker announces victim\'s IP prefixes as their own → internet routes traffic to attacker → MITM, DoS, data theft. Famous incidents: Pakistan Telecom hijacked YouTube (2008), Cloudflare route leak (2019), crypto wallet traffic interception. Detection: 1) **BGP monitoring** - watch route announcements for your ASN (RIPE RIS, RouteViews), 2) **Unexpected ASNs** in path, 3) **More specific prefixes** (attacker announces /24 vs your /22 = more specific wins), 4) **Latency anomalies** (traceroute shows wrong path), 5) **Certificate errors** (traffic MITMed). Defense: 1) **RPKI (Resource Public Key Infrastructure)** - cryptographically sign route announcements, 2) **BGP monitoring services** (BGPmon, ThousandEyes), 3) **IRR filtering**, 4) **Peer validation**, 5) **Anycast for critical services**. MITRE: T1590.001 (IP Addresses).'
    },
    {
        id: 'port59',
        title: 'IPFS Peer-to-Peer Storage',
        points: 7,
        question: 'IPFS (InterPlanetary File System) uses ports 4001 and 8080. What security concerns exist?',
        type: 'checkbox',
        options: [
            { value: 'content', text: 'No control over what content is stored/distributed through your node' },
            { value: 'legal', text: 'Legal liability for hosting illegal content' },
            { value: 'bandwidth', text: 'Bandwidth exhaustion from serving other nodes' },
            { value: 'private', text: 'IPFS provides private encrypted storage by default' }
        ],
        correct: ['content', 'legal', 'bandwidth'],
        mitre: 'T1102',
        explanation: '🌌 IPFS Ports: **4001** = peer-to-peer communication (TCP/UDP), **5001** = API, **8080** = Gateway. IPFS = distributed file system (blockchain storage, NFTs, censorship-resistant hosting). Security/legal risks: 1) **Content liability** - node caches and redistributes content (may include illegal material - CSAM, malware), you become unwitting host, 2) **No takedown mechanism** - content is permanent and distributed, 3) **Bandwidth abuse** - pinning large files, serving millions of requests, 4) **Malware distribution** - immutable malware hosting, phishing sites, 5) **Privacy leak** - DHT exposes what you\'ve accessed. Legit uses: Archival, decentralized apps. Defense: 1) **Private IPFS clusters** (authorized peers only), 2) **Content filtering**, 3) **Bandwidth limits**, 4) **Monitor what\'s pinned**, 5) **Legal compliance review**. Similar: BitTorrent, Dat. MITRE: T1102 (Web Service - dead drop).'
    },
    {
        id: 'port60',
        title: 'WireGuard VPN Protocol',
        points: 7,
        question: 'WireGuard VPN uses UDP port 51820. How does its security model differ from traditional VPNs?',
        type: 'radio',
        options: [
            { value: 'pubkey', text: 'Public key cryptography only - no shared secrets or certificates' },
            { value: 'password', text: 'Password-based authentication like PPTP' },
            { value: 'token', text: 'Token-based authentication like SSO' },
            { value: 'anonymous', text: 'Anonymous access by default' }
        ],
        correct: 'pubkey',
        mitre: 'T1090.003',
        explanation: '🔐 Port 51820 (UDP, configurable) = WireGuard VPN. **Modern cryptography approach**: 1) **Public/private keys only** - no passwords, no PKI/CAs, no shared secrets, 2) **Silent handshake** - port scan shows nothing (unlike OpenVPN), 3) **Minimal attack surface** - 4,000 lines of code vs 600,000 (OpenVPN), 4) **Perfect forward secrecy** - compromise doesn\'t expose past traffic, 5) **Roaming** - maintains connection across IP changes (mobile friendly). Security benefits: Resistant to known VPN exploits (no TLS vulnerabilities). Risks: 1) **Key management** - if private key stolen, attacker has permanent VPN access until key rotated, 2) **No MFA** - pubkey only (add external auth layer), 3) **Static IPs** - peer enumeration easier. Defense: 1) **Protect private keys** (HSM, secure storage), 2) **Regular key rotation**, 3) **Audit allowed peers**, 4) **Combine with SSO/MFA at app layer**. MITRE: T1090.003 (Multi-hop Proxy - though VPN is legit use).'
    },
    {
        id: 'port61',
        title: 'CoAP IoT Protocol Security',
        points: 8,
        question: 'CoAP (Constrained Application Protocol) for IoT uses UDP port 5683. What makes it vulnerable?',
        type: 'checkbox',
        options: [
            { value: 'lightweight', text: 'Lightweight protocol lacks security features for constrained devices' },
            { value: 'amplification', text: 'CoAP amplification DDoS attacks' },
            { value: 'discovery', text: 'Service discovery exposes all IoT devices' },
            { value: 'encrypted', text: 'CoAP enforces DTLS encryption by default' }
        ],
        correct: ['lightweight', 'amplification', 'discovery'],
        mitre: 'T1498.002',
        explanation: '📡 CoAP Ports: **5683** (UDP, unencrypted), **5684** (DTLS encrypted). CoAP = HTTP for IoT (MQTT alternative). Vulnerabilities: 1) **No security by default** - DTLS optional, many implementations skip it (performance/battery), 2) **Amplification attacks** - small request to /.well-known/core → large directory response (amplification factor 10-40x), 3) **Service discovery** - exposes all resources/sensors on device, 4) **Spoofing** - UDP-based, no handshake → easy to spoof, 5) **Constrained devices** - can\'t handle crypto overhead, may disable security. Shodan: 100K+ exposed CoAP endpoints. Attack: Map IoT infrastructure, amplification DDoS, manipulate sensors (temp, alarms). Defense: 1) **Always use CoAPS** (port 5684 with DTLS), 2) **Network segmentation** (IoT VLAN), 3) **Rate limiting**, 4) **Authentication** (pre-shared keys, certs), 5) **Disable discovery on internet-facing**. MITRE: T1498.002 (Reflection Amplification).'
    },
    {
        id: 'port62',
        title: 'Prometheus Metrics Exposure',
        points: 7,
        question: 'Prometheus monitoring exposes /metrics endpoint on port 9090. What sensitive data can leak?',
        type: 'checkbox',
        options: [
            { value: 'topology', text: 'Complete infrastructure topology and service dependencies' },
            { value: 'internal', text: 'Internal IPs, hostnames, and service versions' },
            { value: 'business', text: 'Business metrics revealing revenue, user counts, activity' },
            { value: 'none', text: 'Metrics are anonymized and safe to expose' }
        ],
        correct: ['topology', 'internal', 'business'],
        mitre: 'T1590',
        explanation: '📊 Port 9090 = Prometheus web UI, 9100 = Node Exporter. Prometheus scrapes metrics from all infrastructure. Open /metrics = **reconnaissance goldmine**: 1) **Infrastructure map** - all services, nodes, databases, load balancers, dependencies, 2) **Internal details** - hostnames (db-master-01), IPs (10.0.5.0/24), software versions (postgres:13.2 - search CVEs), 3) **Business intel** - request rates, error rates, revenue streams, customer counts, 4) **Performance data** - CPU/mem → identify weak targets, 5) **API endpoints** - http_requests_total by endpoint label. Real breaches: Exposed Prometheus revealed entire AWS architecture. Attack: Map network → identify vulnerable versions → prioritize targets. Defense: 1) **Authentication** (basic auth, OAuth proxy), 2) **Network restrictions** (internal only), 3) **Scrub sensitive labels**, 4) **Aggregation** (Thanos with access control), 5) **Separate metrics tiers** (public vs internal). MITRE: T1590 (Gather Victim Network Information).'
    },
    {
        id: 'port63',
        title: 'RTMP Streaming Protocol Injection',
        points: 8,
        question: 'RTMP (Real-Time Messaging Protocol) on port 1935 is used for live streaming. What attacks are possible?',
        type: 'checkbox',
        options: [
            { value: 'inject', text: 'Stream injection - inject malicious content into live broadcasts' },
            { value: 'hijack', text: 'Stream hijacking - replace legitimate stream with attacker content' },
            { value: 'extract', text: 'Extract stream keys and restream to unauthorized platforms' },
            { value: 'readonly', text: 'RTMP is receive-only and cannot be attacked' }
        ],
        correct: ['inject', 'hijack', 'extract'],
        mitre: 'T1557',
        explanation: '📹 Port 1935 (TCP) = RTMP (Adobe Flash-based streaming - Twitch, YouTube Live, OBS). Security flaws: 1) **Weak authentication** - stream keys are static passwords (easily leaked), 2) **No stream integrity** - MITM can inject frames (propaganda, malware QR codes), 3) **Stream hijacking** - if key leaked, attacker publishes to same URL → takes over broadcast, 4) **Unencrypted** - RTMP sends data plaintext (RTMPS is encrypted but less common), 5) **Key extraction** - compromise streaming PC → steal keys → restream to competitor platforms (copyright violations). Real attacks: Twitch stream takeovers, political stream defacement. Defense: 1) **Rotate stream keys regularly**, 2) **Use RTMPS** (TLS encryption), 3) **IP whitelisting** (only authorized IPs can publish), 4) **Monitor active streams** (detect simultaneous connections), 5) **Watermarking** (detect rogue restreams). Modern: WebRTC, HLS for browser-native. MITRE: T1557 (Man-in-the-Middle).'
    },
    {
        id: 'port64',
        title: 'Consul Service Discovery',
        points: 8,
        question: 'HashiCorp Consul on port 8500 has no ACLs configured. What is the impact?',
        type: 'checkbox',
        options: [
            { value: 'services', text: 'Complete visibility into all microservices and their locations' },
            { value: 'kv', text: 'Access to key-value store containing secrets and configs' },
            { value: 'execute', text: 'Remote code execution via Consul exec command' },
            { value: 'readonly', text: 'Default mode is read-only for safety' }
        ],
        correct: ['services', 'kv', 'execute'],
        mitre: 'T1482',
        explanation: '🔍 Consul Ports: **8500** = HTTP API/UI, **8301** = LAN gossip, **8600** = DNS interface. No ACLs = **full cluster compromise**: 1) **Service enumeration** - map entire microservices architecture (endpoints, IPs, health), 2) **Key-value store** - extract database passwords, API keys, TLS certs stored in Consul KV, 3) **Service registration** - register malicious service → traffic redirected to attacker (MITM/data theft), 4) **Consul exec** - `consul exec <command>` runs on all nodes (cluster-wide RCE), 5) **Intention spoofing** - bypass service mesh security policies. Defense: 1) **Enable ACL system** (bootstrap ACLs, generate tokens), 2) **Default deny policy**, 3) **Namespace isolation**, 4) **TLS for all interfaces**, 5) **Audit logs**, 6) **Network segmentation**. Similar: etcd, ZooKeeper risks. MITRE: T1482 (Domain Trust Discovery - though service mesh).'
    },
    {
        id: 'port65',
        title: 'AMQP Message Queue Security',
        points: 7,
        question: 'AMQP (Advanced Message Queuing Protocol) on port 5672 is used by enterprise message brokers. What security risks exist?',
        type: 'checkbox',
        options: [
            { value: 'queues', text: 'Unauthorized access to message queues containing sensitive data' },
            { value: 'poison', text: 'Message poisoning to trigger application vulnerabilities' },
            { value: 'replay', text: 'Message replay attacks if no deduplication' },
            { value: 'encrypted', text: 'AMQP messages are encrypted end-to-end by default' }
        ],
        correct: ['queues', 'poison', 'replay'],
        mitre: 'T1557',
        explanation: '📬 Port 5672 = AMQP (RabbitMQ, Apache Qpid, Azure Service Bus). Security issues: 1) **Authentication bypass** - default creds (guest/guest in RabbitMQ), weak passwords, 2) **Message eavesdropping** - unencrypted AMQP exposes message content (use AMQPS 5671), 3) **Queue poisoning** - publish malicious messages with SQL injection, XXE, deserialization exploits → compromise consumers, 4) **Replay attacks** - capture and replay financial transactions, commands if no message IDs/timestamps, 5) **Routing manipulation** - alter exchange bindings → messages go to attacker queue, 6) **DoS** - publish massive messages, exhaust broker memory. Defense: 1) **Strong authentication + TLS**, 2) **Per-queue/exchange ACLs**, 3) **Input validation at consumers**, 4) **Message signing** (verify sender), 5) **Idempotency** (deduplication), 6) **Rate limiting + quotas**, 7) **Network isolation**. MITRE: T1557 (MITM on message bus).'
    },
    {
        id: 'port66',
        title: 'GraphQL Over WebSocket',
        points: 7,
        question: 'GraphQL subscriptions use WebSocket connections (typically port 443 or 4000). What unique attack vectors exist?',
        type: 'checkbox',
        options: [
            { value: 'dos', text: 'Subscription DoS by requesting expensive real-time queries' },
            { value: 'auth', text: 'WebSocket connections may bypass REST API authentication' },
            { value: 'injection', text: 'GraphQL injection through subscription parameters' },
            { value: 'readonly', text: 'Subscriptions are read-only and cannot modify data' }
        ],
        correct: ['dos', 'auth', 'injection'],
        mitre: 'T1499',
        explanation: '🔌 GraphQL Subscriptions = real-time data over WebSocket. Attack vectors: 1) **Subscription DoS** - subscribe to expensive queries (deeply nested, N+1 queries) → maintain 1000s of connections → exhaust server (CPU, memory, DB), 2) **Auth bypass** - WebSocket upgrades may skip auth middleware, token validation only at HTTP upgrade (not per message), 3) **GraphQL injection** - subscription filters with SQL-like syntax ($where: "id = 1 OR 1=1") → injection, 4) **Rate limit bypass** - REST APIs have rate limits, WebSockets stay open indefinitely, 5) **Information disclosure** - subscribe to admin channels without proper authorization checks, 6) **Batching attacks** - send 100 subscriptions in one connection. Defense: 1) **Auth on every message** (not just connection), 2) **Query complexity limits**, 3) **Depth limiting**, 4) **Rate limits per connection**, 5) **Input validation/parameterization**, 6) **Subscription allowlist**, 7) **Monitor active subscriptions**. Tools: graphql-ws, Apollo Server. MITRE: T1499 (Endpoint DoS).'
    },
    {
        id: 'port67',
        title: 'DHCPv6 Spoofing Attack',
        points: 8,
        question: 'DHCPv6 uses UDP port 547. What network attack can be performed via DHCPv6 spoofing?',
        type: 'radio',
        options: [
            { value: 'mitm', text: 'Man-in-the-middle via rogue DNS server assignment' },
            { value: 'dos_only', text: 'Denial of service only - no data interception' },
            { value: 'amplification', text: 'DDoS amplification attacks' },
            { value: 'safe', text: 'DHCPv6 has built-in authentication preventing spoofing' }
        ],
        correct: 'mitm',
        mitre: 'T1557.003',
        explanation: '🌐 DHCPv6 Ports: **547** (server), **546** (client). **DHCPv6 Spoofing Attack**: 1) Attacker sends rogue Router Advertisement (RA) + DHCPv6 responses, 2) Victim configures IPv6 address and uses attacker\'s DNS server, 3) **DNS spoofing** → redirect traffic, phishing, credential theft, 4) **Works even with RA Guard** (SLAAC prevention) if DHCPv6 not protected. Unlike IPv4 DHCP, IPv6 has both SLAAC + DHCPv6 (more attack surface). Mitigation challenges: 1) **RA Guard/DHCPv6 Guard** - switch feature to drop rogue messages (but fragmentation bypasses exist), 2) **SEND (Secure Neighbor Discovery)** - cryptographic RA protection (rarely deployed), 3) **Disable IPv6** (not sustainable long-term). Real attack: Evil twin attacks in coffee shops, enterprise MITMs. Defense: 1) **IPv6 First Hop Security** (RA/DHCP Guard, ND Inspection), 2) **Monitor for rogue RAs**, 3) **802.1X port security**, 4) **DNSSEC** (validate DNS responses). MITRE: T1557.003 (DHCP Spoofing).'
    },
    {
        id: 'port68',
        title: 'InfluxDB Time-Series Database',
        points: 7,
        question: 'InfluxDB on port 8086 has no authentication. What sensitive data might be exposed?',
        type: 'checkbox',
        options: [
            { value: 'metrics', text: 'Application performance metrics and business KPIs' },
            { value: 'iot', text: 'IoT sensor data and industrial telemetry' },
            { value: 'rce', text: 'Remote code execution via InfluxQL injection' },
            { value: 'anonymous', text: 'Time-series data is anonymized and contains no sensitive info' }
        ],
        correct: ['metrics', 'iot', 'rce'],
        mitre: 'T1213',
        explanation: '⏱️ Port 8086 = InfluxDB (time-series database for metrics, IoT, monitoring). Unauthenticated access risks: 1) **Data exfiltration** - extract all measurements: application metrics (request rates, errors, latency), business metrics (revenue, signups, conversions), IoT data (sensor readings, location), infrastructure telemetry, 2) **InfluxQL injection** - similar to SQL injection: `SELECT * FROM users WHERE name=\'admin\' OR 1=1--\'` (older versions), 3) **Write arbitrary data** - pollute metrics, trigger false alerts, hide incidents, 4) **Reconnaissance** - database names reveal application architecture, retention policies show data importance. CVE-2019-20933: JWT bypass. Defense: 1) **Enable authentication** (v1: [http] auth-enabled=true, v2: built-in), 2) **User permissions** (read/write/admin separation), 3) **Network isolation**, 4) **TLS encryption**, 5) **Input validation** (parameterized queries), 6) **Retention policies** (limit exposure window). Similar: TimescaleDB, Prometheus. MITRE: T1213 (Data from Information Repositories).'
    },
    {
        id: 'port69',
        title: 'mTLS Certificate Authentication',
        points: 8,
        question: 'Service mesh requires mTLS on all service-to-service communication. What security benefits does this provide?',
        type: 'checkbox',
        options: [
            { value: 'identity', text: 'Strong cryptographic identity for every service' },
            { value: 'encryption', text: 'Encrypted communications between all services' },
            { value: 'authz', text: 'Foundation for authorization policies (identity-based rules)' },
            { value: 'firewall', text: 'Eliminates need for network segmentation and firewalls' }
        ],
        correct: ['identity', 'encryption', 'authz'],
        mitre: 'T1040',
        explanation: '🔐 mTLS (Mutual TLS) = both client and server present certificates (vs standard TLS where only server authenticates). **Service mesh benefits**: 1) **Strong identity** - every service has cryptographic identity (X.509 cert), no IP-based trust, 2) **Encryption** - all service-to-service traffic encrypted (prevents network sniffing in compromised VPC/cluster), 3) **Authentication** - verify caller identity (service A can trust request is from service B), 4) **Authorization foundation** - policies based on identity ("payments service can only call order service"), 5) **Short-lived certs** - auto-rotation (hours/days) limits blast radius, 6) **No shared secrets** - eliminates password sprawl. Does NOT replace: Firewalls still needed (defense-in-depth), input validation, application-layer auth (user identity). Challenges: 1) Certificate management at scale, 2) Performance overhead (TLS handshakes), 3) Certificate provisioning complexity. Tools: Istio, Linkerd, Consul Connect, SPIFFE/SPIRE. MITRE: T1040 (Network Sniffing - prevention).'
    },
    {
        id: 'port70',
        title: 'Port-Based Network Access Control',
        points: 9,
        question: 'IEEE 802.1X uses EAP over EAPOL (no specific port, Layer 2). What attack bypasses 802.1X?',
        type: 'radio',
        options: [
            { value: 'hub', text: 'Ethernet hub between authenticated device and switch' },
            { value: 'dos', text: 'DoS attack against RADIUS server' },
            { value: 'weak_eap', text: 'Weak EAP methods like LEAP' },
            { value: 'impossible', text: '802.1X cannot be bypassed' }
        ],
        correct: 'hub',
        mitre: 'T1200',
        explanation: '🔒 802.1X = port-based NAC. Device must authenticate (via RADIUS) before network access granted. **Hub in the middle attack**: 1) Legitimate laptop authenticates → switch port goes to "authorized" state, 2) Attacker connects Ethernet hub between laptop and wall jack, 3) Connects their device to hub, 4) Switch sees authenticated MAC (laptop) → allows traffic, 5) Attacker\'s device piggybacks on authenticated session. Other bypass methods: 1) **MAC spoofing** - clone authenticated device MAC (works if no 802.1X on specific port), 2) **EAPOL logoff** - send deauth frame → force reauthentication → capture credentials, 3) **RADIUS server DoS** → failopen mode (some switches), 4) **Credential theft** - weak EAP (LEAP crackable, EAP-MD5 no mutual auth). Defense: 1) **EAP-TLS** (certificate-based, strongest), 2) **MACsec** (Layer 2 encryption - encrypted 802.1X), 3) **Port security** (MAC limiting), 4) **Encrypted EAP methods** (PEAP, EAP-TTLS with proper CA validation), 5) **NAC posture checks** (beyond just auth). MITRE: T1200 (Hardware Additions).'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = portsExtended;
}
