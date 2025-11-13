# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This repository contains a **SOC Analyst Professional Training Platform** - an interactive web-based assessment application for Tier-1 SOC Analyst training and evaluation. This is an educational web application, not a traditional software development project.

## Contents

- **index.html**: Main single-page web application (1,520 lines) with complete UI, timer, scoring, and achievement system
- **questions_data.js**: Question database containing 300 questions (50 per category, 5,767 lines, 469KB)
- **test_syntax.js**: Legacy validation script (deprecated)

## Application Architecture

### Technology Stack
- Pure HTML5/CSS3/JavaScript (no frameworks)
- Client-side only (no backend required)
- LocalStorage for session persistence
- Responsive design with CSS Grid

### Core Features

1. **7 Assessment Categories** (35 questions total per session - 5 random from each category):
   - Networking Fundamentals (25pts) - 🌐
   - Web Application Security (30pts) - 🔓
   - Firewall Rules (25pts) - 🛡️
   - Malware Analysis (25pts) - 🦠
   - Security Infrastructure (15pts) - 📡
   - Ports & Protocols (20pts) - 🔌
   - Log Analysis (30pts) - 📊

2. **Question Randomization**:
   - 50 unique questions per category in database
   - 5 random questions selected per session from each category
   - Same questions persist across session restores
   - Questions stored with IDs: `net1-50`, `web1-50`, `fw1-50`, `mal1-50`, `dev1-50`, `port1-50`, `log1-50`

3. **Achievement System**:
   - 10 tiers per category (Novice → Legend)
   - Tracks unique questions answered across all sessions
   - Progress persists in localStorage
   - Modal popup with category tabs
   - Badge counter on main interface

4. **Session Management**:
   - 90-minute timer (5,400 seconds)
   - Auto-save progress to localStorage
   - 24-hour session expiration
   - Optional session restore on page reload
   - Declines clear all progress including achievements

5. **Scoring System**:
   - Points normalized to total exactly 100
   - Partial credit for checkbox questions
   - Immediate feedback on answer submission
   - Final score calculation with grade (Pass ≥70%)

6. **Question Types**:
   - Single choice (radio)
   - Multiple choice (checkbox)
   - Dropdown matching
   - Text area (manual grading)

## Key Technical Implementation Details

### Session Persistence (index.html:1991-2023)
```javascript
localStorage.setItem('socAnalystProgress', JSON.stringify({
    totalScore, questionScores, timeRemaining,
    selectedQuestionIds, timestamp
}));
```

### Achievement Tracking (index.html:1279-1287)
```javascript
categoryProgress = {
    networking: new Set(),
    webattacks: new Set(),
    // ... tracks unique question IDs answered
}
```

### Question Filtering (index.html:1756-1758)
```javascript
// Skip already-answered questions on session restore
if (questionScores[q.id] !== undefined) {
    return { html: '', wasSkipped: true };
}
```

### Point Normalization (index.html:1574-1597)
- Calculates scale factor to ensure exactly 100 total points
- Adjusts for rounding errors
- Distributes points proportionally across all questions

## Security & Learning Topics Covered

### Attack Techniques
- XSS, SQL Injection, CSRF, Path Traversal
- Brute force authentication
- Lateral movement (SMB)
- Command & Control (IRC, Tor)
- DNS tunneling / DGA
- Privilege escalation
- IDOR exploitation
- Phishing / BEC
- Data exfiltration

### Security Indicators
- IRC traffic (port 6667)
- Tor connections (port 9001, 185.220.101.0/24)
- PowerShell encoded commands (`-enc`, `-ep bypass`)
- mimikatz on Domain Controllers
- Double extensions (.pdf.exe)
- Sequential port scanning
- Workstation-to-workstation SMB
- Impossible travel scenarios

### MITRE ATT&CK Techniques
- T1110: Brute Force
- T1021.002: SMB/Windows Admin Shares
- T1071.001: Application Layer Protocol (C2)
- T1568.002: Domain Generation Algorithms
- T1547.001: Registry Run Keys
- T1053.005: Scheduled Task
- T1543.003: Windows Service
- T1059.001: PowerShell

## Working with This Repository

### Running the Application
1. Open `index.html` in a modern web browser
2. No build process or dependencies required
3. Works entirely offline after initial load

### Modifying Questions
Edit `questions_data.js`:
- Each category must have exactly 50 questions
- Question IDs follow pattern: `{category}{1-50}`
- Each question has: `id`, `type`, `question`, `options`, `correct`, `points`, `explanation`

### Common Development Tasks

**Adding a new question category:**
1. Add category to `questionBank` object in questions_data.js
2. Add category tab in index.html (tab-nav section)
3. Add category to `categoryProgress` and `categoryInfo` objects
4. Update `getCategoryFromQuestionId()` function
5. Add rendering logic in `renderQuiz()` function

**Modifying point allocation:**
- Points are automatically normalized to 100 total
- Change `points` property in individual questions
- Normalization happens at runtime (index.html:1574-1597)

**Adjusting achievement tiers:**
- Edit `categoryAchievements` array (index.html:1290-1301)
- Each tier has: `questions`, `name`, `icon`, `color`

### No Build/Test Commands

This is a static web application with no build process. Testing is done by:
1. Opening index.html in browser
2. Validating questions_data.js syntax: `node --check questions_data.js`
3. Manual testing of UI/UX features

### File Structure
```
SOC-Analyst-Pro/
├── index.html           # Main application (1,520 lines)
├── questions_data.js    # Question database (5,767 lines, 469KB)
├── test_syntax.js       # Legacy validator (deprecated)
└── CLAUDE.md           # This file
```

## Known Constraints

- Questions must be answered in order within each category
- Cannot skip questions (must answer to proceed)
- Timer continues even when tab is inactive
- LocalStorage-based (not synced across devices)
- No backend for persistence or analytics
- Manual grading required for text area questions

## Browser Compatibility

Requires modern browser with:
- ES6 JavaScript support
- LocalStorage API
- CSS Grid
- Flexbox
- Custom CSS properties (CSS variables)
