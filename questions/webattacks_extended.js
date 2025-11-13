/**
 * Extended Web Attacks Questions (web51-100)
 * Lazy-loaded when user clicks "Load More Questions"
 *
 * Current Status: web51-60 complete (10 questions)
 * Base questions (web1-50) are in questions_data.js
 */

const webattacksExtended = [
    {
        id: 'web51',
        title: 'JWT Token Manipulation',
        points: 12,
        question: 'A JWT token has header: {"alg":"none","typ":"JWT"}. What vulnerability does this indicate?',
        type: 'radio',
        options: [
            { value: 'alg_none', text: 'Algorithm confusion - accepts unsigned tokens' },
            { value: 'weak_secret', text: 'Weak signing secret' },
            { value: 'expired', text: 'Expired token' },
            { value: 'replay', text: 'Replay attack vulnerability' },
            { value: 'injection', text: 'SQL injection in claims' }
        ],
        correct: 'alg_none',
        explanation: '🔓 JWT "alg:none" Attack: Some libraries accept "none" algorithm = no signature verification! Attacker modifies payload (change user_id, elevate role to admin), sets alg:none, removes signature. Server accepts it as valid. CVE-2015-9235, CVE-2016-10555. Defense: Reject "none" algorithm, validate signature algorithm whitelist, use strong secrets (HS256/RS256). Tools: jwt_tool, Burp JWT Editor. Common in bug bounties. Interview: "How do you secure JWTs?"'
    },
    {
        id: 'web52',
        title: 'GraphQL Introspection',
        points: 10,
        question: 'Penetration tester sends GraphQL query: __schema{types{name,fields{name}}}. What information is being gathered?',
        type: 'radio',
        options: [
            { value: 'schema', text: 'Complete API schema including hidden endpoints' },
            { value: 'users', text: 'User database records' },
            { value: 'passwords', text: 'Password hashes' },
            { value: 'keys', text: 'API keys and secrets' },
            { value: 'logs', text: 'Application logs' }
        ],
        correct: 'schema',
        explanation: '🔍 GraphQL Introspection: Built-in feature allowing clients to query schema structure. Reveals all types, queries, mutations, fields = complete API documentation. Attackers find hidden endpoints, understand data relationships, craft precise attacks. Defense: Disable introspection in production, authentication on sensitive queries, rate limiting. Tools: InQL, GraphQL Voyager. Different from REST (no OpenAPI doc by default). Interview: "GraphQL security vs REST?"'
    },
    {
        id: 'web53',
        title: 'CORS Misconfiguration',
        points: 11,
        question: 'Response header: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. What is the risk?',
        type: 'radio',
        options: [
            { value: 'invalid', text: 'Invalid config - wildcard cannot be used with credentials' },
            { value: 'xss', text: 'Cross-Site Scripting vulnerability' },
            { value: 'sqli', text: 'SQL injection exposure' },
            { value: 'csrf', text: 'CSRF token bypass' },
            { value: 'open_redirect', text: 'Open redirect to any origin' }
        ],
        correct: 'invalid',
        explanation: '⚠️ CORS Misconfiguration: Cannot use wildcard (*) with credentials:true = browsers reject it for security. Common mistake: Developers want "allow all origins" + cookies. Correct fix: Reflect Origin header (but validate whitelist!). Vulnerable: Reflecting any origin without validation. Attack: Malicious site makes authenticated requests, steals data. Defense: Whitelist specific origins, avoid null origin, no regex bypass. CWE-942. Interview: "Explain CORS and SOP."'
    },
    {
        id: 'web54',
        title: 'Insecure Deserialization',
        points: 13,
        question: 'Java application deserializes user-controlled cookie containing serialized object. What is the critical risk?',
        type: 'radio',
        options: [
            { value: 'rce', text: 'Remote Code Execution via gadget chains' },
            { value: 'xss', text: 'Cross-Site Scripting' },
            { value: 'sqli', text: 'SQL Injection' },
            { value: 'dos', text: 'Denial of Service only' },
            { value: 'info_leak', text: 'Information disclosure only' }
        ],
        correct: 'rce',
        explanation: '💥 Insecure Deserialization: Deserializing untrusted data = RCE in Java/PHP/.NET. Attack: Craft malicious serialized object using "gadget chains" (Commons Collections, Spring, etc.), server deserializes = arbitrary code execution. Famous: Apache Commons exploit, Java RMI attacks. Defense: Never deserialize untrusted data, use JSON/protobuf instead, whitelist classes if must deserialize. OWASP Top 10 #8. Tools: ysoserial, phpggc. Critical severity vulnerability.'
    },
    {
        id: 'web55',
        title: 'HTTP Request Smuggling',
        points: 14,
        question: 'Attacker sends conflicting Content-Length and Transfer-Encoding headers. What attack is this?',
        type: 'radio',
        options: [
            { value: 'smuggling', text: 'HTTP Request Smuggling (CL.TE or TE.CL desync)' },
            { value: 'splitting', text: 'HTTP Response Splitting' },
            { value: 'pollution', text: 'HTTP Parameter Pollution' },
            { value: 'overflow', text: 'Buffer overflow' },
            { value: 'injection', text: 'Header injection' }
        ],
        correct: 'smuggling',
        explanation: '🚢 HTTP Request Smuggling: Frontend/backend servers disagree on request boundaries. CL.TE: Frontend uses Content-Length, backend uses Transfer-Encoding (chunked). Attacker smuggles second request inside first. Impacts: Bypass security controls, poison cache, hijack requests, access admin panels. Defense: Normalize requests, reject ambiguous headers, HTTP/2. Tools: Smuggler, Burp Suite. Advanced attack, high severity. Interview: "Explain request smuggling types."'
    },
    {
        id: 'web56',
        title: 'NoSQL Injection',
        points: 10,
        question: 'MongoDB query: db.users.find({username: req.body.username, password: req.body.password}). Attacker sends: {"username": "admin", "password": {"$ne": null}}. What happens?',
        type: 'radio',
        options: [
            { value: 'bypass', text: 'Authentication bypass - $ne operator matches any password' },
            { value: 'error', text: 'Database error' },
            { value: 'blocked', text: 'Request blocked by validation' },
            { value: 'crash', text: 'Application crash' },
            { value: 'nothing', text: 'Query fails safely' }
        ],
        correct: 'bypass',
        explanation: '🔓 NoSQL Injection: Injecting operators like $ne (not equal), $gt (greater than), $where. Query becomes: {username:"admin", password:{$ne:null}} = "password is not null" (always true for admin). Bypasses authentication! PHP arrays enable this: username=admin&password[$ne]=null. Defense: Type checking, ORM/ODM, whitelist operators, never use $where with user input. Similar attacks: $regex for enumeration. Tools: NoSQLMap. Different from SQL injection but same impact.'
    },
    {
        id: 'web57',
        title: 'Server-Side Template Injection',
        points: 12,
        question: 'Application renders user input in template: {{user.name}}. Tester inputs: {{7*7}} and sees "49" in output. What vulnerability?',
        type: 'radio',
        options: [
            { value: 'ssti', text: 'Server-Side Template Injection (SSTI)' },
            { value: 'xss', text: 'Cross-Site Scripting' },
            { value: 'sqli', text: 'SQL Injection' },
            { value: 'rce', text: 'Direct Remote Code Execution' },
            { value: 'calc', text: 'Calculator feature working correctly' }
        ],
        correct: 'ssti',
        explanation: '🔥 SSTI (Server-Side Template Injection): Template engine evaluates expressions in user input. {{7*7}}=49 confirms SSTI. Escalate to RCE: Jinja2: {{config.__class__.__init__.__globals__["os"].popen("whoami").read()}}, Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("whoami")}. Defense: Sandbox templates, avoid rendering user input in templates, use logic-less templates. Affects: Jinja2, Twig, Freemarker, Velocity, Smarty. Critical vulnerability.'
    },
    {
        id: 'web58',
        title: 'Race Condition Exploitation',
        points: 11,
        question: 'E-commerce site has $100 balance. Attacker sends 10 simultaneous purchase requests for $100 item. What is the risk?',
        type: 'radio',
        options: [
            { value: 'race', text: 'Race condition - multiple purchases before balance check completes' },
            { value: 'dos', text: 'Denial of Service attack' },
            { value: 'overflow', text: 'Integer overflow' },
            { value: 'sqli', text: 'SQL injection' },
            { value: 'blocked', text: 'All requests safely rejected' }
        ],
        correct: 'race',
        explanation: '⏱️ Race Condition: Time-of-check to time-of-use (TOCTOU) vulnerability. All 10 requests check balance ($100) before any deduct it = 10 purchases complete. Also known as: Business logic race condition, parallel execution flaw. Famous: Marcus Hutchins Uber bounty ($10k). Defense: Database transactions with locking, atomic operations, idempotency keys, rate limiting. Test: Burp Suite Turbo Intruder, simultaneous requests. Common in: Payment processing, voucher redemption, voting systems. CWE-362.'
    },
    {
        id: 'web59',
        title: 'OAuth Implicit Flow Attack',
        points: 13,
        question: 'OAuth 2.0 implicit flow returns access token in URL fragment: redirect_uri#access_token=abc123. Why is this insecure?',
        type: 'radio',
        options: [
            { value: 'fragment', text: 'URL fragment logged in browser history, referrer headers, leaked' },
            { value: 'encrypted', text: 'Token not encrypted in transit' },
            { value: 'csrf', text: 'Vulnerable to CSRF attacks' },
            { value: 'sqli', text: 'SQL injection in token parameter' },
            { value: 'secure', text: 'This is actually secure' }
        ],
        correct: 'fragment',
        explanation: '🔐 OAuth Implicit Flow Risks: Access token in URL fragment (#) appears in: 1) Browser history, 2) Referrer headers to third-party sites, 3) Logs, 4) Shoulder surfing. No refresh token = cannot revoke. Defense: Use Authorization Code flow with PKCE instead, never implicit flow for confidential data. OAuth 2.0 Security Best Practices (RFC 8252) deprecates implicit flow. Modern: Authorization Code + PKCE for SPAs. Interview: "OAuth flows and their security?"'
    },
    {
        id: 'web60',
        title: 'Clickjacking Defense',
        points: 9,
        question: 'Which HTTP header prevents clickjacking attacks?',
        type: 'radio',
        options: [
            { value: 'xfo', text: 'X-Frame-Options: DENY or SAMEORIGIN' },
            { value: 'csp', text: 'Content-Security-Policy: default-src' },
            { value: 'hsts', text: 'Strict-Transport-Security' },
            { value: 'coop', text: 'Cross-Origin-Opener-Policy' },
            { value: 'cors', text: 'Access-Control-Allow-Origin' }
        ],
        correct: 'xfo',
        explanation: '🖱️ Clickjacking Defense: X-Frame-Options: DENY (no framing) or SAMEORIGIN (same domain only). Also: CSP frame-ancestors directive (more flexible). Attack: Attacker embeds your site in invisible iframe, tricks users to click while thinking they click attacker\'s site. Impacts: Unintended actions (delete account, transfer money, change password). Famous: Twitter "Don\'t Click" worm, Facebook Like button. Modern: frame-ancestors in CSP preferred over X-Frame-Options. CWE-1021. Interview: "Explain clickjacking and defenses."'
    }
];

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = webattacksExtended;
}
