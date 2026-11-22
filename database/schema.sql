-- LOGIN TWIN CANONICAL DATABASE SCHEMA
-- SQLite with PRAGMA foreign_keys = ON

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst', -- 'student', 'analyst', 'administrator'
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS url_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submitted_url TEXT NOT NULL,
    normalized_host TEXT NOT NULL,
    score INTEGER NOT NULL,
    risk_level TEXT NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    scanned_at TEXT NOT NULL,
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS url_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    points INTEGER NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES url_scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS simulation_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL, -- e.g. 'PH-001'
    title TEXT NOT NULL,
    content_json TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS simulation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER NOT NULL,
    user_id INTEGER,
    selected_answers_json TEXT NOT NULL,
    score INTEGER NOT NULL,
    completed_at TEXT NOT NULL,
    FOREIGN KEY (scenario_id) REFERENCES simulation_scenarios(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    source TEXT NOT NULL, -- 'sample_file', 'demo_generator', 'app_auth', 'url_scan'
    event_type TEXT NOT NULL, -- 'login', 'access_denied', 'request_invalid', etc.
    outcome TEXT NOT NULL, -- 'success', 'failure', 'denied', 'invalid', 'unknown'
    source_ip TEXT,
    account_id TEXT,
    resource TEXT,
    details_json TEXT,
    severity_hint TEXT
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_code TEXT UNIQUE NOT NULL, -- 'DET-001', 'DET-002', etc.
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    threshold_json TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE NOT NULL,
    rule_id INTEGER NOT NULL,
    severity TEXT NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New', -- 'New', 'Investigating', 'Resolved', 'Closed'
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    confidence INTEGER NOT NULL DEFAULT 80,
    FOREIGN KEY (rule_id) REFERENCES detection_rules(id)
);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES security_events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_type TEXT NOT NULL, -- 'shared_ip', 'account_targeted', 'attack_sequence'
    correlation_key TEXT NOT NULL,
    explanation TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS correlation_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id INTEGER NOT NULL,
    event_id INTEGER,
    alert_id INTEGER,
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES security_events(id) ON DELETE SET NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
    status TEXT NOT NULL DEFAULT 'New', -- 'New', 'Investigating', 'Resolved', 'Closed'
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, alert_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    actor_id INTEGER,
    old_status TEXT,
    new_status TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    action TEXT NOT NULL, -- 'LOG_INGEST', 'ALERT_STATUS_UPDATE', 'INCIDENT_CREATE', etc.
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details_json TEXT,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Essential Performance Indexes
CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(event_time);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_time ON security_events(source_ip, event_time);
CREATE INDEX IF NOT EXISTS idx_security_events_acc_time ON security_events(account_id, event_time);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type, outcome);
CREATE INDEX IF NOT EXISTS idx_alerts_status_sev ON alerts(status, severity);
CREATE INDEX IF NOT EXISTS idx_url_scans_date ON url_scans(scanned_at);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
