import re

KNOWLEDGE_BASE = [
    {
        "keywords": ["url", "analyzer", "scanner", "url-001", "url-002", "url-003", "rules", "link", "homograph", "punycode"],
        "category": "URL Threat Analyzer",
        "title": "Module 1: Advanced URL Threat Analyzer",
        "badge": "Deterministic Engine",
        "answer": (
            "### 🔍 Module 1: Advanced URL Threat Analyzer\n\n"
            "**Purpose:** Inspects URL syntax and risk indicators locally using predefined deterministic rules without making outbound HTTP requests.\n\n"
            "**Key Principles & Boundaries:**\n"
            "- **Zero Network Requests (FR-02):** The analyzer parses the text using Python's `urllib.parse` only. It never accesses, opens, or crawls the target website.\n"
            "- **8 Deterministic Rules:**\n"
            "  1. `URL-001`: Non-HTTPS scheme (+5 pts)\n"
            "  2. `URL-002`: IP-literal hostname (+20 pts)\n"
            "  3. `URL-003`: Suspicious security keywords (+5 pts each, max +15 pts)\n"
            "  4. `URL-004`: Excessive URL length (>75 chars) (+10 pts)\n"
            "  5. `URL-005`: Unusual subdomain depth (>= 3 dots) (+10 pts)\n"
            "  6. `URL-006`: Obfuscated patterns, high % encoding, or '@' masking (+10 pts)\n"
            "  7. `URL-007`: Known URL shortener host (`bit.ly`, `tinyurl.com`, etc.) (+10 pts)\n"
            "  8. `URL-008`: Unicode / Punycode (`xn--`) homograph indicators (+15 pts)\n\n"
            "**Scoring & Phrasing:** Bounded heuristic score from 0 to 100. Uses standardized UI wording: *'No strong indicators found by these checks'* (0-19 Low) and *'Potentially suspicious – verify independently'* (20-100)."
        ),
        "suggestions": ["What are the 8 URL rules?", "Why does URL Analyzer avoid network requests?", "How does the Phishing Lab work?"]
    },
    {
        "keywords": ["phishing", "quiz", "awareness", "lab", "simulation", "scenarios", "training", "ph-001", "password"],
        "category": "Phishing Quiz & Awareness",
        "title": "Module 2: Phishing Quiz & Awareness Platform",
        "badge": "Safe Quiz Mode",
        "answer": (
            "### 🛡️ Module 2: Phishing Quiz & Awareness Platform\n\n"
            "**Purpose:** Interactive educational quizzes teaching participants to spot social engineering, header deception, and phishing lures through realistic controlled scenarios.\n\n"
            "**Safety & Privacy Guarantee (FR-05):**\n"
            "- Uses reserved RFC domains (`.example.invalid`) so learners never connect to live malicious infrastructure.\n"
            "- **Zero Password Collection:** The quiz interface never presents a live password input, never collects credentials, and never stores private authentication tokens.\n\n"
            "**5 Built-in Training Scenarios:**\n"
            "- `PH-001`: Unexpected Urgent Account Verification (24h threat lure)\n"
            "- `PH-002`: Urgent Direct Deposit Payroll Routing Failure (financial urgency)\n"
            "- `PH-003`: Failed Parcel Delivery & Address Reschedule (delivery smishing)\n"
            "- `PH-004`: Mandatory IT Multi-Factor Authentication (MFA) Re-sync (IT helpdesk lure)\n"
            "- `PH-005`: Confidential Executive Bonus Review Document (curiosity lure)\n\n"
            "**Evaluation Scoring:** Computes an objective 0–100% awareness grade: up to 60 points for indicator identification accuracy + 40 points for selecting the proper defensive action."
        ),
        "suggestions": ["How are phishing scores calculated?", "Explain the SOC Monitoring pipeline", "What is Brute Force detection?"]
    },
    {
        "keywords": ["soc", "events", "monitoring", "ingest", "ingestion", "canonical", "schema", "logs"],
        "category": "SOC Monitoring",
        "title": "Module 3: SOC Security Monitoring & Ingestion",
        "badge": "SIEM Pipeline",
        "answer": (
            "### 📡 Module 3: SOC Security Event Monitoring\n\n"
            "**Purpose:** Receives structured security logs, validates their structure, normalizes them into a canonical schema, and executes real-time detection rules.\n\n"
            "**Canonical Schema Attributes:**\n"
            "- `event_id`: Integer primary key\n"
            "- `event_time`: ISO-8601 UTC timestamp\n"
            "- `ingested_at`: UTC timestamp of arrival\n"
            "- `source`: Origin (`sample_file`, `demo_generator`, `app_auth`)\n"
            "- `event_type`: Standardized (`login`, `access_denied`, `request_invalid`, `url_scan`)\n"
            "- `outcome`: Categorized (`success`, `failure`, `denied`, `invalid`)\n"
            "- `source_ip`: Normalized IPv4/IPv6 address\n"
            "- `account_id`: Target pseudonymized user\n"
            "- `resource`: URI or target endpoint\n\n"
            "**Ingestion Safety:** Transactional batch insertion. Malformed JSON is safely rejected without corrupting the database."
        ),
        "suggestions": ["How do I ingest JSON logs?", "Explain the 5 detection rules", "What is Event Correlation?"]
    },
    {
        "keywords": ["detection", "rules", "brute force", "det-001", "det-002", "det-003", "det-004", "det-005", "spray", "spraying"],
        "category": "Detection Engine",
        "title": "Detection Engine & Sliding Window Rules",
        "badge": "Multi-Rule SIEM",
        "answer": (
            "### ⚠️ Detection Engine (DET-001 through DET-005)\n\n"
            "The platform implements 5 deterministic rules using sliding time windows and alert deduplication:\n\n"
            "1. **DET-001: Brute Force Detection**\n"
            "   - *Condition:* $\\ge 5$ failed logins for ONE account within 5 minutes (300s).\n"
            "   - *Severity:* **High** | *Confidence:* 85%\n"
            "   - *False Positives:* User mistypes password; test automation scripts.\n\n"
            "2. **DET-002: Password Spraying Detection**\n"
            "   - *Condition:* 1 source IP targeting $\\ge 5$ DISTINCT accounts with failed logins within 10 minutes (600s).\n"
            "   - *Severity:* **High** | *Confidence:* 90%\n"
            "   - *False Positives:* University proxy or corporate egress NAT IP.\n\n"
            "3. **DET-003: Suspicious IP Activity Burst**\n"
            "   - *Condition:* $\\ge 10$ failed, denied, or invalid events from 1 IP within 5 minutes.\n"
            "   - *Severity:* **Medium** | *Confidence:* 75%\n\n"
            "4. **DET-004: Repeated Unauthorized Access**\n"
            "   - *Condition:* $\\ge 5$ `access_denied` events from same IP/account within 5 minutes.\n"
            "   - *Severity:* **Medium** | *Confidence:* 80%\n\n"
            "5. **DET-005: Abnormal Request Activity**\n"
            "   - *Condition:* $\\ge 8$ `request_invalid` events from 1 IP within 2 minutes.\n"
            "   - *Severity:* **Medium** | *Confidence:* 70%\n\n"
            "**Alert Deduplication:** Uses a stable fingerprint `hash(rule_id, grouping_key, time_bucket)` so repeated failures update the existing open alert rather than flooding the dashboard."
        ),
        "suggestions": ["What is brute force vs password spraying?", "How does deduplication work?", "How does Event Correlation work?"]
    },
    {
        "keywords": ["correlation", "correlate", "pivot", "mesh", "cross-rule", "multi-stage"],
        "category": "Event Correlation Engine",
        "title": "Module 4: Security Event Correlation Engine",
        "badge": "Pattern Analysis",
        "answer": (
            "### 🔗 Module 4: Security Event Correlation Engine\n\n"
            "**Purpose:** Groups distinct detection alerts and security events that share a meaningful relationship into a coherent investigation case.\n\n"
            "**How it Operates:**\n"
            "- **Shared Pivot Keys:** Identifies entities sharing a common `source_ip` or `account_id`.\n"
            "- **Time Window Clustering:** Events must occur within configurable sliding windows (e.g. 10 minutes).\n"
            "- **Multi-Rule Attack Chaining:** Correlates multi-phase attacks (e.g., Reconnaissance Spray DET-002 $\\rightarrow$ Brute Force DET-001 $\\rightarrow$ Unauthorized Access DET-004).\n"
            "- **Investigative Caution:** Explains that a shared IP can indicate NAT gateways or shared office proxies; correlation provides leads, not absolute identity proof."
        ),
        "suggestions": ["How do I test correlation?", "Explain Incident Management", "Explain the SHA-256 Hash Chain"]
    },
    {
        "keywords": ["incident", "incidents", "case", "investigation", "lifecycle", "status", "checklist"],
        "category": "Incident Management",
        "title": "Module 5: Incident Investigation & Case Lifecycle",
        "badge": "Analyst Workflow",
        "answer": (
            "### 🚨 Module 5: Incident Management & Case Lifecycle\n\n"
            "**Purpose:** Escalates security alerts into formal investigation cases with full audit accountability.\n\n"
            "**Strict State Machine (Section 6.3):**\n"
            "- `New` $\\rightarrow$ `Investigating` or `Closed` (if confirmed false positive)\n"
            "- `Investigating` $\\rightarrow$ `Resolved` (Mandatory resolution justification note required!) or revert to `New`\n"
            "- `Resolved` $\\rightarrow$ `Closed` or reopen to `Investigating`\n"
            "- `Closed` $\\rightarrow$ Explicit analyst reopen to `Investigating`\n\n"
            "**Built-in Investigation Checklist:**\n"
            "1. Which detection rule fired and threshold crossed?\n"
            "2. What is the evidence time range and count?\n"
            "3. What accounts and IPs are targeted?\n"
            "4. Could this be shared NAT, user error, or test activity?\n"
            "5. What mitigation action was recorded in audit?"
        ),
        "suggestions": ["Explain the Tamper-Evident Hash Chain", "Viva Prep Questions", "How to run URL scans"]
    },
    {
        "keywords": ["audit", "hash", "chain", "sha-256", "sha256", "integrity", "tamper", "tamper-evident", "merkle"],
        "category": "Tamper-Evident Hash Chain",
        "title": "Module 6: Tamper-Evident SHA-256 Audit Hash Chain",
        "badge": "Cryptographic Integrity",
        "answer": (
            "### 📜 Module 6: Tamper-Evident SHA-256 Hash Chaining\n\n"
            "**Purpose:** Records all administrative and analyst actions (log ingest, alert triage, incident updates) in a cryptographically linked ledger.\n\n"
            "**Cryptographic Construction:**\n"
            "- Genesis block starts with 64 zeros: `0000...0000`.\n"
            "- Each row calculates:\n"
            "  $$\\text{Canonical} = \\text{ID} \\parallel \\text{PreviousHash} \\parallel \\text{Action} \\parallel \\text{EntityType} \\parallel \\text{EntityID} \\parallel \\text{Details} \\parallel \\text{CreatedAt}$$\n"
            "  $$\\text{EntryHash} = \\text{SHA-256}(\\text{Canonical})$$\n\n"
            "**One-Click Verification Tool:** Re-computes the entire chain from row 1 to $N$. If any attacker or buggy process tampers with a record's details or timestamp, the stored hash and all downstream hashes will fail verification!\n\n"
            "**Academic Boundary:** Tamper-*evident* (detects tampering under stated assumptions), not tamper-*proof* against an attacker with root database and filesystem rewrite control."
        ),
        "suggestions": ["Viva Questions & Answers", "What is brute force vs spraying?", "Explain URL-001 through URL-008"]
    },
    {
        "keywords": ["viva", "exam", "questions", "interview", "oral", "why sqlite", "false positive", "presentation"],
        "category": "Viva Preparation Guide",
        "title": "B.Tech Viva & Presentation Exam Guide",
        "badge": "Viva Ready",
        "answer": (
            "### 🎓 Top 10 B.Tech Viva Questions & Expected Answers (Section 15.2)\n\n"
            "1. **Why is this a cybersecurity project?**\n"
            "   *Answer:* It integrates URL threat analysis, phishing awareness training, security log monitoring, multi-rule detection, event correlation, and incident triage.\n\n"
            "2. **What is brute force vs password spraying?**\n"
            "   *Answer:* Brute force repeatedly targets one single account with many passwords. Password spraying tries one or few common passwords across many distinct accounts from one source IP.\n\n"
            "3. **Is the URL confirmed malicious?**\n"
            "   *Answer:* No. The score is heuristic and explainable. Local syntax analysis cannot guarantee malice without live contextual verification.\n\n"
            "4. **Why SQLite?**\n"
            "   *Answer:* It is serverless, lightweight, zero-configuration, and sufficient for academic demonstration; it can later be migrated to PostgreSQL.\n\n"
            "5. **What is a false positive?**\n"
            "   *Answer:* A benign activity incorrectly flagged as malicious, such as an employee repeatedly mistyping their password.\n\n"
            "6. **Does hash chaining prevent all tampering?**\n"
            "   *Answer:* No. It provides *tamper-evidence* (detects modifications), but cannot prevent a root attacker with total system control from rewriting both the database and codebase.\n\n"
            "7. **What is the monitoring boundary?**\n"
            "   *Answer:* Only supplied synthetic or authorized logs are processed; the app does not claim to capture all network traffic."
        ),
        "suggestions": ["Explain Module 1: URL Analyzer", "Explain Module 2: Phishing Lab", "Explain Module 3: SOC Ingestion"]
    }
]

DEFAULT_FALLBACK = {
    "title": "Login Twin Cybersecurity Platform Copilot",
    "badge": "AI SOC Assistant",
    "answer": (
        "### 👋 Hello! I am your Login Twin SOC Assistant & Feature Explainer.\n\n"
        "I can help you understand any feature of this platform, explain the cybersecurity logic, or prepare for project presentations and viva exams!\n\n"
        "**What would you like to explore?**\n"
        "- **URL Threat Analyzer:** How the 8 local deterministic rules work without network requests.\n"
        "- **Phishing Awareness Lab:** Educational scenarios, scoring formula, and safe zero-credential policies.\n"
        "- **SOC Security Monitoring:** Canonical log schema, ingestion, and sliding-window rules.\n"
        "- **Detection Rules (DET-001..005):** Brute force, password spraying, suspicious IPs, and thresholds.\n"
        "- **Event Correlation Engine:** Multi-alert pivoting, shared IP grouping, and attack sequence chaining.\n"
        "- **Incident Management:** Incident lifecycle states, investigation checklist, and case notes.\n"
        "- **SHA-256 Hash Chain:** Tamper-evident cryptographic verification and Merkle chaining.\n"
        "- **Viva Prep Guide:** Expected answers to the faculty oral examination questions."
    ),
    "suggestions": [
        "Explain URL Threat Analyzer",
        "What is DET-001 Brute Force?",
        "What is Password Spraying?",
        "How does the SHA-256 Hash Chain work?",
        "Viva Exam Questions & Answers"
    ]
}

def answer_query(query_text):
    if not query_text or not query_text.strip():
        return DEFAULT_FALLBACK

    cleaned = query_text.lower().strip()
    
    # Calculate best match score
    best_entry = None
    best_score = 0

    for entry in KNOWLEDGE_BASE:
        score = 0
        for kw in entry["keywords"]:
            if re.search(r'\b' + re.escape(kw) + r'\b', cleaned):
                score += 3
            elif kw in cleaned:
                score += 1
        if score > best_score:
            best_score = score
            best_entry = entry

    if best_entry and best_score >= 1:
        return {
            "title": best_entry["title"],
            "badge": best_entry["badge"],
            "answer": best_entry["answer"],
            "suggestions": best_entry["suggestions"]
        }

    return DEFAULT_FALLBACK
