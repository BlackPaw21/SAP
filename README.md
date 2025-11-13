# SOC Analyst Professional Training Platform

An interactive web-based assessment application for Tier-1 SOC (Security Operations Center) Analyst training and evaluation. Test your cybersecurity knowledge across 7 critical domains with 300+ questions.

## 🚀 Live Demo

**[Launch Training Platform](https://blackpaw21.github.io/SOC-Analyst-Pro/)**

## 📋 Overview

This platform provides a comprehensive 90-minute assessment covering essential SOC analyst skills. The application runs entirely in your browser with no backend required, featuring automatic session persistence and a progressive achievement system.

### Key Features

- **7 Assessment Categories** - 35 questions per session (5 random from each category)
- **300+ Question Database** - 50 unique questions per category
- **Achievement System** - Track progress with 10 unlockable tiers per category
- **Smart Session Management** - Auto-save with 24-hour session persistence
- **Timer Controls** - Pause/resume functionality with visual feedback
- **Instant Feedback** - Immediate grading with detailed explanations
- **Responsive Design** - Works on desktop, tablet, and mobile devices

## 🎯 Assessment Categories

| Category | Points | Icon | Topics Covered |
|----------|--------|------|----------------|
| **Networking Fundamentals** | 25 | 🌐 | TCP/IP, OSI Model, Network Protocols |
| **Web Application Security** | 30 | 🔓 | XSS, SQL Injection, CSRF, OWASP Top 10 |
| **Firewall Rules** | 25 | 🛡️ | Rule Analysis, Policy Configuration |
| **Malware Analysis** | 25 | 🦠 | Threat Detection, IOC Analysis |
| **Security Infrastructure** | 15 | 📡 | SIEM, IDS/IPS, Security Architecture |
| **Ports & Protocols** | 20 | 🔌 | Common Services, Port Identification |
| **Log Analysis** | 30 | 📊 | Event Correlation, Incident Detection |

**Total: 170 Points** (normalized to 100 for final score)

## 🎓 Achievement Tiers

Progress through 10 tiers in each category by answering questions correctly:

```
🥉 Novice → 🥈 Learner → 🥇 Practitioner → 🏅 Competent → ⭐ Proficient
→ 💎 Expert → 🔥 Master → 👑 Elite → 🚀 Grandmaster → 🏆 Legend
```

## 🛠️ Technology Stack

- **Pure HTML5/CSS3/JavaScript** - No frameworks or dependencies
- **LocalStorage API** - Client-side session persistence
- **CSS Grid & Flexbox** - Responsive layout system
- **Modern ES6+** - Clean, maintainable code

## 📦 Getting Started

### Option 1: Use GitHub Pages (Recommended)

Simply visit the live demo link above - no installation required!

### Option 2: Run Locally

1. **Clone the repository**
   ```bash
   git clone https://github.com/BlackPaw21/SOC-Analyst-Pro.git
   cd SOC-Analyst-Pro
   ```

2. **Open in browser**
   ```bash
   # On macOS
   open index.html

   # On Linux
   xdg-open index.html

   # On Windows
   start index.html
   ```

3. **Or use a local server**
   ```bash
   # Python 3
   python -m http.server 8000

   # Node.js
   npx serve
   ```
   Then navigate to `http://localhost:8000`

## 🎮 How to Use

1. **Start Assessment** - Click "Start New Session" or restore a previous session
2. **Answer Questions** - Work through each category in any order (use keys 1-7 to switch)
3. **Check Answers** - Submit your answer for instant feedback
4. **Track Progress** - Monitor your score and time remaining
5. **Complete Assessment** - Submit final answers when ready
6. **View Results** - See your score, grade, and unlock achievements

### Keyboard Shortcuts

- **1-7** - Switch between categories
- **ESC** - Close modal dialogs
- **Click Timer** - Pause/resume the countdown

## 📝 Customization

### Adding Questions

Edit `questions_data.js` to add or modify questions:

```javascript
{
    id: 'net51',
    type: 'single',
    question: 'Your question here?',
    options: ['Option A', 'Option B', 'Option C', 'Option D'],
    correct: 'Option A',
    points: 5,
    explanation: 'Detailed explanation here...'
}
```

### Adjusting Timer

In `index.html`, modify the timer duration:

```javascript
let timeRemaining = 5400; // 90 minutes in seconds
```

### Modifying Point Values

Points are automatically normalized to 100. Adjust individual question points in `questions_data.js`.

## 🔒 Security Topics Covered

- **Attack Techniques**: XSS, SQLi, CSRF, Path Traversal, Phishing, Data Exfiltration
- **MITRE ATT&CK**: T1110 (Brute Force), T1021.002 (SMB), T1071.001 (C2), T1568.002 (DGA)
- **Threat Detection**: IRC traffic, Tor connections, PowerShell abuse, mimikatz, DNS tunneling
- **Incident Response**: Log correlation, IOC identification, lateral movement detection

