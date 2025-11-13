/**
 * Extended Web Attacks Questions (web51-70)
 * Lazy-loaded when user clicks "Load More Questions"
 */

const webattacksExtended = [
    {
        id: 'web51',
        title: 'CSP Bypass Techniques',
        points: 9,
        question: 'Site has CSP: <code>script-src \'self\' https://trusted-cdn.com</code>. An attacker uploads malicious JS to trusted-cdn.com via JSONP endpoint. What attack is this?',
        type: 'radio',
        options: [
            { value: 'csp_bypass', text: 'CSP bypass via whitelisted domain abuse' },
            { value: 'xss_basic', text: 'Regular reflected XSS' },
            { value: 'blocked', text: 'CSP successfully blocks this' },
            { value: 'dom_xss', text: 'DOM-based XSS only' },
            { value: 'jsonp_only', text: 'JSONP vulnerability unrelated to CSP' }
        ],
        correct: 'csp_bypass',
        explanation: '🛡️ CSP Bypass: Whitelisting entire domains is dangerous. If trusted-cdn.com has JSONP endpoint (/callback?data=), attacker loads: <script src="https://trusted-cdn.com/callback?data=alert(1)"></script>. Other bypasses: Angular libraries on CDN (ng-app + expressions), jQuery JSONP, user-uploaded content on whitelisted domain. Defense: Use \'nonce-\' or \'hash-\' instead of domain whitelist, disable JSONP, use strict-dynamic, report-uri monitoring. CSP is defense-in-depth, not silver bullet. Google CSP Evaluator tool.'
    },
    {
        id: 'web52',
        title: 'Second-Order SQL Injection',
        points: 10,
        question: 'User registers with username: <code>admin\'--</code> (stored safely with prepared statement). Later, admin panel displays users with query: <code>SELECT * FROM logs WHERE user=\'$username\'</code>. What vulnerability?',
        type: 'radio',
        options: [
            { value: 'second_order_sqli', text: 'Second-order SQL injection' },
            { value: 'stored_xss', text: 'Stored XSS' },
            { value: 'no_vuln', text: 'No vulnerability (prepared statement used)' },
            { value: 'first_order_sqli', text: 'First-order SQL injection' },
            { value: 'idor', text: 'IDOR vulnerability' }
        ],
        correct: 'second_order_sqli',
        explanation: '🔄 Second-Order SQLi: Data stored safely but retrieved unsafely. Registration uses prepared statement ✓. Admin panel retrieves username from DB and concatenates into new query ✗. Query becomes: SELECT * FROM logs WHERE user=\'admin\'--\' → comments out rest, returns all logs. Attack delayed: inject → store → retrieve → execute. Also called: Persistent SQLi, Stored SQLi. Defense: Prepared statements EVERYWHERE (storage + retrieval), assume all database data is tainted. Hard to detect with static analysis. CWE-89.'
    },
    {
        id: 'web53',
        title: 'OAuth Token Theft',
        points: 8,
        question: 'OAuth redirect: <code>https://app.com/callback?code=AUTH_CODE</code>. Attacker registers redirect_uri: <code>https://app.com.evil.com/callback</code>. What vulnerability?',
        type: 'radio',
        options: [
            { value: 'redirect_uri_vuln', text: 'Insufficient redirect_uri validation' },
            { value: 'xss', text: 'XSS in OAuth flow' },
            { value: 'csrf', text: 'CSRF in OAuth callback' },
            { value: 'no_vuln', text: 'OAuth provider blocks this' },
            { value: 'open_redirect', text: 'Open redirect only' }
        ],
        correct: 'redirect_uri_vuln',
        explanation: '🔐 OAuth Redirect URI Attack: Provider checks if redirect_uri STARTS with registered domain. app.com.evil.com passes (contains app.com). Authorization code sent to attacker → trade for access token → account takeover. Other bypasses: Path traversal (app.com/../evil.com), open redirect on app.com, URL fragments. Defense: Exact match redirect_uri (no wildcards), register full URLs not domains, use PKCE (Proof Key for Code Exchange) for mobile. OAuth 2.0 Security BCP. Real attacks: Slack, GitHub OAuth bugs.'
    },
    {
        id: 'web54',
        title: 'Web Cache Poisoning',
        points: 10,
        question: 'Attacker sends: <code>X-Forwarded-Host: evil.com</code>. Response includes: <code>&lt;script src="//evil.com/analytics.js"&gt;</code>. Cache stores poisoned response. What attack?',
        type: 'radio',
        options: [
            { value: 'cache_poison', text: 'Web cache poisoning' },
            { value: 'xss', text: 'Reflected XSS only' },
            { value: 'ssrf', text: 'Server-Side Request Forgery' },
            { value: 'header_injection', text: 'HTTP header injection' },
            { value: 'cache_deception', text: 'Web cache deception' }
        ],
        correct: 'cache_poison',
        explanation: '☠️ Web Cache Poisoning: App uses unkeyed header (X-Forwarded-Host) to build URLs. Response cached by Varnish/Cloudflare/CDN. All users get poisoned response with attacker\'s script. Unkeyed inputs: X-Forwarded-Host, X-Original-URL, Accept-Language, User-Agent (sometimes). Impact: Stored XSS-like, affects all cached users. Defense: Never trust proxy headers for content generation, configure cache keys properly, use Cache-Control: private for dynamic content. Discovery: James Kettle (PortSwigger). Tools: Param Miner. Different from cache deception (tricks cache into storing private data).'
    },
    {
        id: 'web55',
        title: 'GraphQL Introspection',
        points: 7,
        question: 'Production GraphQL API responds to: <code>query {__schema {types {name fields {name}}}}</code>. What is exposed?',
        type: 'radio',
        options: [
            { value: 'schema', text: 'Entire API schema including hidden queries/mutations' },
            { value: 'data', text: 'All database records' },
            { value: 'code', text: 'Application source code' },
            { value: 'nothing', text: 'Nothing - introspection is safe' },
            { value: 'users', text: 'User credentials only' }
        ],
        correct: 'schema',
        explanation: '🔍 GraphQL Introspection: Reveals complete API structure - all types, queries, mutations, fields, arguments. Attacker learns: Hidden admin endpoints, deprecated fields (often vulnerable), internal API structure, field relationships. Example: Discovers deletUserPermanently mutation not linked in UI. Defense: **Disable introspection in production** (Apollo: introspection: false), use GraphQL Shield for field-level auth, rate limiting, query depth limiting. Introspection useful for dev, dangerous in prod. Tools: GraphQL Voyager (schema visualization), InQL Scanner. Many APIs leave this enabled by mistake.'
    },
    {
        id: 'web56',
        title: 'SAML Signature Wrapping',
        points: 9,
        question: 'SAML assertion is signed but response is not. Attacker copies signature and wraps unsigned assertion. What attack?',
        type: 'radio',
        options: [
            { value: 'saml_wrapping', text: 'XML Signature Wrapping (XSW)' },
            { value: 'replay', text: 'SAML replay attack' },
            { value: 'mitm', text: 'Man-in-the-Middle attack' },
            { value: 'xxe', text: 'XXE in SAML parsing' },
            { value: 'blocked', text: 'Signature validation prevents this' }
        ],
        correct: 'saml_wrapping',
        explanation: '📜 XML Signature Wrapping: XML allows multiple assertions. Attacker copies valid signature, adds unsigned assertion with admin privileges. Parser validates signature (passes) but processes wrong assertion. Attack: Change user from victim@company.com to admin@company.com. Affects SAML SSO implementations. Defense: Validate signature AND reference URI, sign entire response (not just assertion), use modern SAML libraries (OneLogin, Auth0), certificate pinning. CVE-2018-0489 (Shibboleth), CVE-2017-11427 (OneLogin). Complex attack requiring XML expertise. Tools: SAML Raider (Burp extension).'
    },
    {
        id: 'web57',
        title: 'Prototype Pollution',
        points: 10,
        question: 'JavaScript code: <code>merge(userInput, config)</code>. Attacker sends: <code>{"__proto__": {"isAdmin": true}}</code>. What happens?',
        type: 'radio',
        options: [
            { value: 'prototype_pollution', text: 'Prototype pollution leading to privilege escalation' },
            { value: 'xss', text: 'XSS vulnerability' },
            { value: 'injection', text: 'Code injection' },
            { value: 'blocked', text: 'Validation blocks this' },
            { value: 'dos', text: 'Denial of Service only' }
        ],
        correct: 'prototype_pollution',
        explanation: '⚠️ Prototype Pollution: Merging untrusted objects pollutes Object.prototype. All objects inherit isAdmin: true. Vulnerable: jQuery.extend, lodash.merge (old), hoek.merge. Impact: Bypass authentication, RCE (if prototype property used in eval/exec), DoS. Attack vectors: JSON POST body, query params, cookies. Defense: Use Object.create(null) (no prototype), JSON Schema validation, Object.freeze(Object.prototype), update vulnerable libraries, sanitize __proto__, constructor, prototype keys. CVE-2019-10744 (lodash), CVE-2020-8203. Client-side and server-side (Node.js) vulnerability. Tools: ppmap scanner.'
    },
    {
        id: 'web58',
        title: 'NoSQL Injection',
        points: 8,
        question: 'MongoDB query: <code>db.users.find({username: req.body.user, password: req.body.pass})</code>. Attacker sends: <code>{"user": "admin", "pass": {"$ne": null}}</code>. What happens?',
        type: 'radio',
        options: [
            { value: 'nosql_bypass', text: 'Authentication bypass via NoSQL operator injection' },
            { value: 'sqli', text: 'SQL injection' },
            { value: 'login_fail', text: 'Login fails normally' },
            { value: 'error', text: 'Database error only' },
            { value: 'xss', text: 'XSS in username field' }
        ],
        correct: 'nosql_bypass',
        explanation: '🍃 NoSQL Injection: Query operators ($ne, $gt, $regex, $where) injected via JSON. {password: {$ne: null}} = password not equal to null (always true) → authentication bypass. MongoDB: $where allows JavaScript execution. Other NoSQL DBs affected: CouchDB, Cassandra. Attack examples: {"$where": "sleep(5000)"} (timing), {"$regex": "^a"} (enumerate passwords char-by-char). Defense: Use parameterized queries, validate input types (expect string, reject objects), whitelist allowed fields, disable JavaScript execution ($where), use mongoose with strict schemas. CWE-943. Tools: NoSQLMap.'
    },
    {
        id: 'web59',
        title: 'JWT Key Confusion',
        points: 9,
        question: 'API uses RS256 (asymmetric). Attacker changes header to HS256, signs with public key. What vulnerability?',
        type: 'radio',
        options: [
            { value: 'key_confusion', text: 'Algorithm confusion (RS256 to HS256)' },
            { value: 'weak_secret', text: 'Weak JWT secret' },
            { value: 'none_algorithm', text: 'None algorithm bypass' },
            { value: 'blocked', text: 'Signature validation fails' },
            { value: 'replay', text: 'Token replay attack' }
        ],
        correct: 'key_confusion',
        explanation: '🔑 JWT Algorithm Confusion: RS256 uses private key to sign, public key to verify. HS256 uses shared secret for both. Attacker changes alg: RS256 → HS256, signs with server\'s public key (known to everyone). Server verifies with public key thinking it\'s HS256 secret → accepts forged token. Change payload: "user": "admin". Defense: Enforce algorithm explicitly (verify(token, key, {algorithms: [\'RS256\']})), reject alg header from untrusted tokens, validate kid (key ID). CVE-2015-9235 (multiple libraries). Real-world attack: Auth0, Okta. Tools: jwt_tool. CWE-347.'
    },
    {
        id: 'web60',
        title: 'SSRF with URL Parsers',
        points: 10,
        question: 'SSRF filter blocks localhost, 127.0.0.1, 169.254.x.x. Attacker uses: <code>http://127.1/</code>. What happens?',
        type: 'radio',
        options: [
            { value: 'ssrf_bypass', text: 'SSRF filter bypass - resolves to 127.0.0.1' },
            { value: 'blocked', text: 'Filter successfully blocks it' },
            { value: 'invalid_url', text: 'Invalid URL format' },
            { value: 'dns_error', text: 'DNS resolution error' },
            { value: 'redirect', text: 'Open redirect only' }
        ],
        correct: 'ssrf_bypass',
        explanation: '🌐 SSRF Bypass Techniques: 127.1 = 127.0.0.1 (IP octet omission). Other bypasses: Decimal IP (2130706433), Hex (0x7f.0.0.1), Octal (0177.0.0.1), IPv6 (::1, ::ffff:127.0.0.1), DNS rebinding (points to 1.2.3.4 then 127.0.0.1), redirect chains, @ symbol (http://expected@evil), enclosed alphanumerics (①②⑦.⓪.⓪.①). Metadata: 169.254.169.254 → 169.254.16705 (decimal). Defense: Whitelist destinations, validate after DNS resolution, use URL parser libraries carefully (TOCTOU), disable redirects, network segmentation. Tools: SSRFmap. CWE-918. Parser inconsistencies between validation and request libraries.'
    },
    {
        id: 'web61',
        title: 'Race Condition in Voucher',
        points: 8,
        question: 'E-commerce voucher can be used once. Attacker sends 100 parallel checkout requests with same voucher code. 50 succeed. What vulnerability?',
        type: 'radio',
        options: [
            { value: 'race_condition', text: 'Race condition / TOCTOU' },
            { value: 'idor', text: 'IDOR in voucher system' },
            { value: 'broken_logic', text: 'Business logic flaw only' },
            { value: 'replay', text: 'Replay attack' },
            { value: 'normal', text: 'System working as intended' }
        ],
        correct: 'race_condition',
        explanation: '⚡ Race Condition: Check (voucher valid?) and Use (mark voucher used) not atomic. Multiple requests check simultaneously (all see "unused"), all pass validation, all mark as used. TOCTOU = Time-Of-Check Time-Of-Use. Impact: Financial loss, duplicate accounts, multiple password resets, parallel OAuth token exchange. Defense: Database transactions (BEGIN TRANSACTION, row-level locks), optimistic locking (version numbers), idempotency keys (Stripe pattern), rate limiting, pessimistic locking (SELECT FOR UPDATE). Test: Burp Intruder with single-packet attack, Turbo Intruder. CWE-362. Hard to reproduce reliably.'
    },
    {
        id: 'web62',
        title: 'HTTP Parameter Pollution',
        points: 7,
        question: 'Request: <code>?email=victim@example.com&email=attacker@evil.com</code>. Password reset sent to both. What vulnerability?',
        type: 'radio',
        options: [
            { value: 'hpp', text: 'HTTP Parameter Pollution' },
            { value: 'idor', text: 'IDOR in email parameter' },
            { value: 'logic_flaw', text: 'Business logic flaw only' },
            { value: 'normal', text: 'Normal HTTP behavior' },
            { value: 'xss', text: 'XSS in email field' }
        ],
        correct: 'hpp',
        explanation: '🔀 HTTP Parameter Pollution: Multiple parameters with same name. Behavior varies: PHP/Apache: last value, ASP.NET/IIS: concatenate with comma, JSP/Tomcat: first value, Node.js: array. WAF sees first (victim), app processes last (attacker) → bypass security. Examples: Bypass CSRF checks, modify SQL queries, override access controls. Attack: /reset?email=victim@x.com&email=attacker@x.com. Defense: Reject duplicate parameters, use POST body (harder to pollute), validate parameter count, test framework behavior. Discovery: Luca Carettoni. Tools: Param Miner. CWE-235.'
    },
    {
        id: 'web63',
        title: 'DNS Rebinding',
        points: 9,
        question: 'Attacker domain evil.com: First DNS query returns 1.2.3.4. After 1s, TTL expires, returns 127.0.0.1. What attack is possible?',
        type: 'radio',
        options: [
            { value: 'dns_rebinding', text: 'DNS rebinding to access internal services' },
            { value: 'dns_spoofing', text: 'DNS cache poisoning' },
            { value: 'ssrf', text: 'Basic SSRF' },
            { value: 'mitm', text: 'Man-in-the-Middle attack' },
            { value: 'no_attack', text: 'Normal DNS behavior' }
        ],
        correct: 'dns_rebinding',
        explanation: '🔄 DNS Rebinding: Bypass Same-Origin Policy. User visits evil.com (1.2.3.4), JavaScript makes AJAX to evil.com, DNS re-resolves to 127.0.0.1, browser allows (same origin = evil.com), attacker reads localhost:8080 response. Attack chain: Initial load → JS execution → DNS TTL expires → re-resolve to internal IP → access private network. Target: IoT devices, routers, internal APIs, cloud metadata. Defense: Host header validation, reject private IPs in DNS, DNS pinning, DNSSEC, authenticate internal services. Real-world: MyEtherWallet DNS hijack 2018. Tools: Singularity, Rebind. Complex but powerful.'
    },
    {
        id: 'web64',
        title: 'Email Header Injection',
        points: 7,
        question: 'Contact form: <code>To: support@app.com\\r\\nBcc: spam@evil.com</code> in subject field. What happens?',
        type: 'radio',
        options: [
            { value: 'header_injection', text: 'Email header injection - adds Bcc recipient' },
            { value: 'xss', text: 'XSS in email body' },
            { value: 'normal', text: 'Email sent normally with literal \\r\\n' },
            { value: 'phishing', text: 'Phishing attack only' },
            { value: 'blocked', text: 'Validation prevents this' }
        ],
        correct: 'header_injection',
        explanation: '📧 Email Header Injection: SMTP uses CRLF (\\r\\n) as header delimiter. Injecting newlines adds headers. Attack payloads: Add Bcc (spam), change From (spoofing), add X-Priority: 1, inject body (\\r\\n\\r\\n<body>). mail() function in PHP vulnerable if input not sanitized. Impact: Spam relay, phishing from trusted domain, email harvesting. Defense: Reject \\r, \\n, %0d, %0a in email headers, use email libraries (PHPMailer, Nodemailer), validate email format strictly, don\'t pass user input to headers. CWE-93. Test: Send email with newlines in Subject/From/To.'
    },
    {
        id: 'web65',
        title: 'Mass Assignment',
        points: 8,
        question: 'User update: <code>PUT /profile</code> with JSON: <code>{"name": "John", "isAdmin": true}</code>. ORM updates all fields. What vulnerability?',
        type: 'radio',
        options: [
            { value: 'mass_assignment', text: 'Mass assignment / Over-posting' },
            { value: 'idor', text: 'IDOR vulnerability' },
            { value: 'privilege_escalation', text: 'Vertical privilege escalation' },
            { value: 'normal', text: 'Normal API behavior' },
            { value: 'authorization', text: 'Broken authorization only' }
        ],
        correct: 'mass_assignment',
        explanation: '📝 Mass Assignment: ORM (Mongoose, ActiveRecord, Entity Framework) auto-binds request parameters to model fields. Attacker adds hidden fields: isAdmin, role, credits, verified. Impact: Privilege escalation (user → admin), bypass payment (price: 0), verify email without token. Famous: GitHub 2012 (add public keys to any repo). Defense: Whitelist allowed fields explicitly, use DTOs (Data Transfer Objects), read-only properties, separate models for input/output. Rails: strong parameters, Express: explicitly list fields. CWE-915, OWASP Top 10 #8. Affects all frameworks with auto-binding.'
    },
    {
        id: 'web66',
        title: 'Client-Side Encryption Bypass',
        points: 6,
        question: 'Password encrypted in browser before sending. Attacker modifies JavaScript to skip encryption. What is the security issue?',
        type: 'radio',
        options: [
            { value: 'client_trust', text: 'Client-side security controls can be bypassed' },
            { value: 'mitm', text: 'Man-in-the-Middle attack only' },
            { value: 'xss', text: 'XSS vulnerability' },
            { value: 'secure', text: 'Encryption provides adequate security' },
            { value: 'weak_crypto', text: 'Weak encryption algorithm' }
        ],
        correct: 'client_trust',
        explanation: '⚠️ Client-Side Security: Never trust client-side validation, encryption, or access control. User controls browser: disable JavaScript, modify code, use Burp proxy, browser console. "Security by obscurity" fails. Examples: Price validation in JS, role checks in JS, rate limiting in JS, obfuscated code. Defense: Server-side validation ALWAYS, client-side validation for UX only, assume all client data is malicious, use TLS (not client-side crypto), server-side authorization. Client-side encryption only useful for zero-knowledge (E2EE like Signal), not for authentication. Security principle: Defense in depth, server is truth. CWE-602.'
    },
    {
        id: 'web67',
        title: 'API Key Exposure',
        points: 7,
        question: 'Which locations expose API keys to attackers? (Select ALL)',
        type: 'checkbox',
        options: [
            { value: 'client_js', text: 'Embedded in client-side JavaScript' },
            { value: 'mobile_app', text: 'Hardcoded in mobile app binary' },
            { value: 'git_history', text: 'Committed to public Git repository' },
            { value: 'server_env', text: 'Server environment variables' },
            { value: 'server_config', text: 'Server configuration files (not web-accessible)' },
            { value: 'database', text: 'Database (encrypted)' }
        ],
        correct: ['client_js', 'mobile_app', 'git_history'],
        explanation: '🔑 API Key Exposure: Client-side = public. JavaScript: View source, DevTools. Mobile: Decompile APK/IPA (jadx, apktool), strings binary. Git: GitHub search, git log --all, deleted commits still accessible. Impact: Abuse quota, data theft, financial loss (AWS keys). Defense: Never put secrets in client code, use backend proxy for API calls, rotate keys immediately if exposed, use API gateway (key per user), monitor usage. Git: .gitignore credentials, scan with git-secrets/TruffleHog, BFG Repo-Cleaner to remove from history. Server env vars are safe if server not compromised. Real cases: AWS keys in GitHub → $50k bill. CWE-798.'
    },
    {
        id: 'web68',
        title: 'Server-Side Template Injection (SSTI)',
        points: 10,
        question: 'Template: <code>Welcome {{username}}</code> in Twig. Attacker sets username: <code>{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}</code>. What happens?',
        type: 'radio',
        options: [
            { value: 'ssti_rce', text: 'Remote Code Execution via SSTI' },
            { value: 'xss', text: 'XSS only' },
            { value: 'safe', text: 'Template engine escapes this' },
            { value: 'error', text: 'Syntax error only' },
            { value: 'sqli', text: 'SQL injection' }
        ],
        correct: 'ssti_rce',
        explanation: '🔥 SSTI RCE: Template engines execute code server-side. Payload exploits Twig/PHP internals to register exec() as filter, then calls it with "id" command. Each engine has unique exploitation: Jinja2: {{config.__class__.__init__.__globals__}}, Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}, ERB: <%= system("id") %>. Impact: Full server compromise, read files, reverse shell. Detection: {{7*7}}, ${7*7}, <%= 7*7 %> → see if evaluated. Defense: Never render_template_string with user input, sandbox templates (Jinja2 SandboxedEnvironment), use logic-less templates (Mustache). Tools: tplmap, PayloadsAllTheThings. CWE-94.'
    },
    {
        id: 'web69',
        title: 'Subdomain Takeover',
        points: 8,
        question: 'DNS shows: <code>blog.company.com CNAME old-bucket.s3.amazonaws.com</code>. Bucket doesn\'t exist. Attacker creates it. What happens?',
        type: 'radio',
        options: [
            { value: 'subdomain_takeover', text: 'Subdomain takeover - attacker controls blog.company.com' },
            { value: 'dns_hijack', text: 'DNS hijacking only' },
            { value: 'safe', text: 'AWS prevents this' },
            { value: 'sqli', text: 'SQL injection in subdomain' },
            { value: 'phishing', text: 'Phishing attack only' }
        ],
        correct: 'subdomain_takeover',
        explanation: '🎯 Subdomain Takeover: Dangling DNS record points to deleted resource. Attacker claims resource (S3 bucket, GitHub Pages, Heroku app, Azure blob). Now controls company subdomain. Impact: Phishing (users trust company.com), steal cookies (*.company.com domain), XSS on main site (if relaxed CSP), bypass SPF/DMARC (email spoofing). Services affected: AWS S3, Azure, GitHub Pages, Heroku, Shopify, Tumblr, WordPress. Detection: Tools like subjack, can-i-take-over-xyz list. Defense: Delete DNS records when decommissioning services, monitor DNS, verify ownership, use CAA records. Real-world: Uber, Starbucks, Shopify subdomains. CWE-350.'
    },
    {
        id: 'web70',
        title: 'Insecure Direct Object Reference (IDOR)',
        points: 7,
        question: 'API endpoint: <code>GET /api/invoice/12345</code> returns user invoice. Changing to 12346 returns other user\'s invoice. What is missing?',
        type: 'radio',
        options: [
            { value: 'authorization', text: 'Authorization check (verify invoice belongs to user)' },
            { value: 'authentication', text: 'Authentication only' },
            { value: 'encryption', text: 'Data encryption' },
            { value: 'input_validation', text: 'Input validation only' },
            { value: 'rate_limiting', text: 'Rate limiting' }
        ],
        correct: 'authorization',
        explanation: '🔓 IDOR (Insecure Direct Object Reference): Application exposes internal object IDs without verifying ownership. Authenticated ✓ but not authorized ✗. Attack: Enumerate IDs (1, 2, 3...), access other users\' data. Impact: Read private documents, modify others\' profiles, delete resources, financial fraud. Examples: Bank statements, medical records, private messages, admin panels. Defense: Verify object ownership (SELECT * WHERE id=X AND user_id=current_user), use UUIDs instead of sequential IDs, indirect references (session mapping), proper ACL. OWASP Top 10 #1 (Broken Access Control). CWE-639. Test: Change ID in URL/POST/cookie.'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = webattacksExtended;
}
