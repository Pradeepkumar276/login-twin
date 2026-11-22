import json
import hashlib
from datetime import datetime, timezone
from database.db import get_db_connection

def current_utc_iso():
    return datetime.now(timezone.utc).isoformat()

# ==================== URL SCANS ====================

def create_url_scan(submitted_url, normalized_host, score, risk_level, findings, user_id=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        cur.execute(
            """INSERT INTO url_scans (submitted_url, normalized_host, score, risk_level, scanned_at, user_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (submitted_url, normalized_host, score, risk_level, now_utc, user_id)
        )
        scan_id = cur.lastrowid
        for finding in findings:
            cur.execute(
                """INSERT INTO url_findings (scan_id, rule_id, title, explanation, points)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, finding["rule_id"], finding["title"], finding["explanation"], finding["points"])
            )
        conn.commit()
        return scan_id
    finally:
        conn.close()

def get_recent_url_scans(limit=25):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT s.*, COUNT(f.id) as finding_count
               FROM url_scans s
               LEFT JOIN url_findings f ON s.id = f.scan_id
               GROUP BY s.id
               ORDER BY s.scanned_at DESC LIMIT ?""",
            (limit,)
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

def get_url_scan_by_id(scan_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM url_scans WHERE id = ?", (scan_id,))
        scan = cur.fetchone()
        if not scan:
            return None
        scan_dict = dict(scan)
        cur.execute("SELECT * FROM url_findings WHERE scan_id = ?", (scan_id,))
        scan_dict["findings"] = [dict(row) for row in cur.fetchall()]
        return scan_dict
    finally:
        conn.close()

# ==================== PHISHING SCENARIOS ====================

def get_active_scenarios():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM simulation_scenarios WHERE is_active = 1 ORDER BY code ASC")
        rows = cur.fetchall()
        scenarios = []
        for r in rows:
            data = json.loads(r["content_json"])
            data["id"] = r["id"]
            scenarios.append(data)
        return scenarios
    finally:
        conn.close()

def get_scenario_by_code(code):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM simulation_scenarios WHERE code = ?", (code,))
        r = cur.fetchone()
        if not r:
            return None
        data = json.loads(r["content_json"])
        data["db_id"] = r["id"]
        return data
    finally:
        conn.close()

def save_simulation_event(scenario_id, selected_answers, score, user_id=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        cur.execute(
            """INSERT INTO simulation_events (scenario_id, user_id, selected_answers_json, score, completed_at)
               VALUES (?, ?, ?, ?, ?)""",
            (scenario_id, user_id, json.dumps(selected_answers), score, now_utc)
        )
        event_id = cur.lastrowid
        conn.commit()
        return event_id
    finally:
        conn.close()

def get_simulation_history(limit=25):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT e.*, s.code as scenario_code, s.title as scenario_title
               FROM simulation_events e
               JOIN simulation_scenarios s ON e.scenario_id = s.id
               ORDER BY e.completed_at DESC LIMIT ?""",
            (limit,)
        )
        rows = cur.fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["selected_answers"] = json.loads(item["selected_answers_json"])
            results.append(item)
        return results
    finally:
        conn.close()

# ==================== SECURITY EVENTS ====================

def insert_security_event(event_dict):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        event_time = event_dict.get("event_time", now_utc)
        cur.execute(
            """INSERT INTO security_events (event_time, ingested_at, source, event_type, outcome, source_ip, account_id, resource, details_json, severity_hint)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_time,
                now_utc,
                event_dict.get("source", "manual"),
                event_dict.get("event_type", "unknown"),
                event_dict.get("outcome", "unknown"),
                event_dict.get("source_ip"),
                event_dict.get("account_id"),
                event_dict.get("resource"),
                json.dumps(event_dict.get("details", {})),
                event_dict.get("severity_hint")
            )
        )
        event_id = cur.lastrowid
        conn.commit()
        return event_id
    finally:
        conn.close()

def insert_security_events_batch(events_list, source="sample_file"):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        inserted_ids = []
        for e in events_list:
            event_time = e.get("event_time", now_utc)
            cur.execute(
                """INSERT INTO security_events (event_time, ingested_at, source, event_type, outcome, source_ip, account_id, resource, details_json, severity_hint)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_time,
                    now_utc,
                    source,
                    e.get("event_type", "unknown"),
                    e.get("outcome", "unknown"),
                    e.get("source_ip"),
                    e.get("account_id"),
                    e.get("resource"),
                    json.dumps(e.get("details", {})),
                    e.get("severity_hint")
                )
            )
            inserted_ids.append(cur.lastrowid)
        conn.commit()
        return inserted_ids
    finally:
        conn.close()

def get_security_events(limit=50, filters=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []
        if filters:
            if filters.get("event_type"):
                query += " AND event_type = ?"
                params.append(filters["event_type"])
            if filters.get("outcome"):
                query += " AND outcome = ?"
                params.append(filters["outcome"])
            if filters.get("source_ip"):
                query += " AND source_ip LIKE ?"
                params.append(f"%{filters['source_ip']}%")
            if filters.get("account_id"):
                query += " AND account_id LIKE ?"
                params.append(f"%{filters['account_id']}%")
            if filters.get("source"):
                query += " AND source = ?"
                params.append(filters["source"])
        query += " ORDER BY event_time DESC, id DESC LIMIT ?"
        params.append(limit)
        cur.execute(query, params)
        rows = cur.fetchall()
        events = []
        for r in rows:
            item = dict(r)
            item["details"] = json.loads(item["details_json"]) if item["details_json"] else {}
            events.append(item)
        return events
    finally:
        conn.close()

def get_event_by_id(event_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM security_events WHERE id = ?", (event_id,))
        row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        item["details"] = json.loads(item["details_json"]) if item["details_json"] else {}
        return item
    finally:
        conn.close()

# ==================== DETECTION RULES & ALERTS ====================

def get_detection_rules():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM detection_rules ORDER BY rule_code ASC")
        rows = cur.fetchall()
        rules = []
        for r in rows:
            item = dict(r)
            item["thresholds"] = json.loads(item["threshold_json"]) if item["threshold_json"] else {}
            rules.append(item)
        return rules
    finally:
        conn.close()

def get_detection_rule_by_code(rule_code):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM detection_rules WHERE rule_code = ?", (rule_code,))
        row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        item["thresholds"] = json.loads(item["threshold_json"]) if item["threshold_json"] else {}
        return item
    finally:
        conn.close()

def get_open_alert_by_fingerprint(fingerprint):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM alerts WHERE fingerprint = ? AND status IN ('New', 'Investigating')",
            (fingerprint,)
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def save_or_update_alert(fingerprint, rule_id, severity, title, description, event_ids, confidence=85):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        cur.execute(
            "SELECT id, event_count FROM alerts WHERE fingerprint = ? AND status IN ('New', 'Investigating')",
            (fingerprint,)
        )
        existing = cur.fetchone()
        if existing:
            alert_id = existing["id"]
            new_count = existing["event_count"] + len(event_ids)
            cur.execute(
                """UPDATE alerts SET last_seen = ?, event_count = ?, description = ? WHERE id = ?""",
                (now_utc, new_count, description, alert_id)
            )
        else:
            cur.execute(
                """INSERT INTO alerts (fingerprint, rule_id, severity, title, description, status, first_seen, last_seen, event_count, confidence)
                   VALUES (?, ?, ?, ?, ?, 'New', ?, ?, ?, ?)""",
                (fingerprint, rule_id, severity, title, description, now_utc, now_utc, len(event_ids), confidence)
            )
            alert_id = cur.lastrowid

        # Attach events to alert_events
        for eid in event_ids:
            cur.execute(
                "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                (alert_id, eid)
            )
        conn.commit()
        return alert_id
    finally:
        conn.close()

def get_alerts(limit=50, status=None, severity=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        query = """SELECT a.*, r.rule_code, r.name as rule_name
                   FROM alerts a
                   JOIN detection_rules r ON a.rule_id = r.id
                   WHERE 1=1"""
        params = []
        if status:
            query += " AND a.status = ?"
            params.append(status)
        if severity:
            query += " AND a.severity = ?"
            params.append(severity)
        query += " ORDER BY a.last_seen DESC LIMIT ?"
        params.append(limit)
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def get_alert_by_id(alert_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT a.*, r.rule_code, r.name as rule_name
               FROM alerts a
               JOIN detection_rules r ON a.rule_id = r.id
               WHERE a.id = ?""",
            (alert_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        alert_dict = dict(row)
        
        # Evidence events
        cur.execute(
            """SELECT e.* FROM security_events e
               JOIN alert_events ae ON e.id = ae.event_id
               WHERE ae.alert_id = ?
               ORDER BY e.event_time DESC""",
            (alert_id,)
        )
        events_rows = cur.fetchall()
        evidence_events = []
        for er in events_rows:
            e_item = dict(er)
            e_item["details"] = json.loads(e_item["details_json"]) if e_item["details_json"] else {}
            evidence_events.append(e_item)
        alert_dict["evidence_events"] = evidence_events
        return alert_dict
    finally:
        conn.close()

def update_alert_status(alert_id, new_status):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
        conn.commit()
    finally:
        conn.close()

# ==================== CORRELATION ====================

def create_correlation(correlation_type, correlation_key, explanation, start_time, end_time, event_ids, alert_ids):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        cur.execute(
            """INSERT INTO correlations (correlation_type, correlation_key, explanation, start_time, end_time, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (correlation_type, correlation_key, explanation, start_time, end_time, now_utc)
        )
        cid = cur.lastrowid
        for eid in event_ids:
            cur.execute(
                "INSERT INTO correlation_members (correlation_id, event_id, alert_id) VALUES (?, ?, NULL)",
                (cid, eid)
            )
        for aid in alert_ids:
            cur.execute(
                "INSERT INTO correlation_members (correlation_id, event_id, alert_id) VALUES (?, NULL, ?)",
                (cid, aid)
            )
        conn.commit()
        return cid
    finally:
        conn.close()

def get_correlations(limit=30):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM correlations ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        corrs = []
        for r in rows:
            c = dict(r)
            cur.execute("SELECT COUNT(DISTINCT event_id) FROM correlation_members WHERE correlation_id = ? AND event_id IS NOT NULL", (c["id"],))
            c["event_count"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT alert_id) FROM correlation_members WHERE correlation_id = ? AND alert_id IS NOT NULL", (c["id"],))
            c["alert_count"] = cur.fetchone()[0]
            corrs.append(c)
        return corrs
    finally:
        conn.close()

def get_correlation_by_id(correlation_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM correlations WHERE id = ?", (correlation_id,))
        row = cur.fetchone()
        if not row:
            return None
        c = dict(row)
        # get member events
        cur.execute(
            """SELECT e.* FROM security_events e
               JOIN correlation_members cm ON e.id = cm.event_id
               WHERE cm.correlation_id = ? ORDER BY e.event_time ASC""",
            (correlation_id,)
        )
        events = []
        for er in cur.fetchall():
            ei = dict(er)
            ei["details"] = json.loads(ei["details_json"]) if ei["details_json"] else {}
            events.append(ei)
        c["events"] = events

        # get member alerts
        cur.execute(
            """SELECT a.*, r.rule_code FROM alerts a
               JOIN correlation_members cm ON a.id = cm.alert_id
               JOIN detection_rules r ON a.rule_id = r.id
               WHERE cm.correlation_id = ? ORDER BY a.last_seen DESC""",
            (correlation_id,)
        )
        c["alerts"] = [dict(ar) for ar in cur.fetchall()]
        return c
    finally:
        conn.close()

# ==================== INCIDENTS ====================

def create_incident(title, severity, summary, alert_ids=None, actor_id=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        cur.execute(
            """INSERT INTO incidents (title, severity, status, summary, created_at, updated_at)
               VALUES (?, ?, 'New', ?, ?, ?)""",
            (title, severity, summary, now_utc, now_utc)
        )
        incident_id = cur.lastrowid
        if alert_ids:
            for aid in alert_ids:
                cur.execute(
                    "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
                    (incident_id, aid)
                )
                cur.execute("UPDATE alerts SET status = 'Investigating' WHERE id = ?", (aid,))
        cur.execute(
            """INSERT INTO incident_history (incident_id, actor_id, old_status, new_status, note, created_at)
               VALUES (?, ?, NULL, 'New', 'Incident created from security alert triage.', ?)""",
            (incident_id, actor_id, now_utc)
        )
        conn.commit()
        return incident_id
    finally:
        conn.close()

def get_incidents(status=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        cur.execute(query, params)
        rows = cur.fetchall()
        incidents = []
        for r in rows:
            inc = dict(r)
            cur.execute("SELECT COUNT(*) FROM incident_alerts WHERE incident_id = ?", (inc["id"],))
            inc["alert_count"] = cur.fetchone()[0]
            incidents.append(inc)
        return incidents
    finally:
        conn.close()

def get_incident_by_id(incident_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cur.fetchone()
        if not row:
            return None
        inc = dict(row)
        # get linked alerts
        cur.execute(
            """SELECT a.*, r.rule_code, r.name as rule_name FROM alerts a
               JOIN incident_alerts ia ON a.id = ia.alert_id
               JOIN detection_rules r ON a.rule_id = r.id
               WHERE ia.incident_id = ? ORDER BY a.last_seen DESC""",
            (incident_id,)
        )
        inc["alerts"] = [dict(ar) for ar in cur.fetchall()]
        
        # get history
        cur.execute("SELECT * FROM incident_history WHERE incident_id = ? ORDER BY created_at ASC", (incident_id,))
        inc["history"] = [dict(hr) for hr in cur.fetchall()]
        return inc
    finally:
        conn.close()

def update_incident_status(incident_id, new_status, note="", actor_id=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        cur.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,))
        r = cur.fetchone()
        if not r:
            return False
        old_status = r["status"]
        closed_at = now_utc if new_status == "Closed" else None
        
        cur.execute(
            """UPDATE incidents SET status = ?, updated_at = ?, closed_at = ? WHERE id = ?""",
            (new_status, now_utc, closed_at, incident_id)
        )
        cur.execute(
            """INSERT INTO incident_history (incident_id, actor_id, old_status, new_status, note, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (incident_id, actor_id, old_status, new_status, note, now_utc)
        )
        # Also update linked alerts if incident is closed/resolved
        if new_status in ("Resolved", "Closed"):
            cur.execute(
                """UPDATE alerts SET status = ? WHERE id IN (
                    SELECT alert_id FROM incident_alerts WHERE incident_id = ?
                )""",
                (new_status, incident_id)
            )
        conn.commit()
        return True
    finally:
        conn.close()

def add_incident_note(incident_id, note, actor_id=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        cur.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,))
        r = cur.fetchone()
        if not r:
            return False
        current_status = r["status"]
        cur.execute(
            """INSERT INTO incident_history (incident_id, actor_id, old_status, new_status, note, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (incident_id, actor_id, current_status, current_status, note, now_utc)
        )
        cur.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now_utc, incident_id))
        conn.commit()
        return True
    finally:
        conn.close()

# ==================== TAMPER-EVIDENT AUDIT LOG ====================

def add_audit_log(action, entity_type, entity_id, details=None, actor_id=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now_utc = current_utc_iso()
        details_str = json.dumps(details or {}, sort_keys=True)
        
        # Get previous row's entry_hash
        cur.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
        last_row = cur.fetchone()
        previous_hash = last_row["entry_hash"] if last_row else "0" * 64

        cur.execute("SELECT MAX(id) FROM audit_logs")
        max_id_row = cur.fetchone()
        next_id = (max_id_row[0] or 0) + 1

        canonical_content = f"{next_id}|{previous_hash}|{action}|{entity_type}|{entity_id}|{details_str}|{now_utc}"
        entry_hash = hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()

        cur.execute(
            """INSERT INTO audit_logs (id, actor_id, action, entity_type, entity_id, details_json, previous_hash, entry_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (next_id, actor_id, action, entity_type, str(entity_id), details_str, previous_hash, entry_hash, now_utc)
        )
        conn.commit()
        return next_id
    finally:
        conn.close()

def get_audit_logs(limit=100):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        logs = []
        for r in rows:
            item = dict(r)
            item["details"] = json.loads(item["details_json"]) if item["details_json"] else {}
            logs.append(item)
        return logs
    finally:
        conn.close()

def verify_audit_chain():
    """
    Verifies cryptographic hash chain integrity across all audit records.
    Returns: (is_valid, count_verified, message, mismatch_info)
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        rows = cur.fetchall()
        if not rows:
            return True, 0, "No audit records found to verify.", None

        expected_prev = "0" * 64
        for idx, row in enumerate(rows):
            r_id = row["id"]
            prev_hash = row["previous_hash"]
            action = row["action"]
            entity_type = row["entity_type"]
            entity_id = row["entity_id"]
            details_json = row["details_json"]
            entry_hash = row["entry_hash"]
            created_at = row["created_at"]

            if idx > 0 and prev_hash != expected_prev:
                return False, idx, f"Chain linkage broken at record ID {r_id}! Previous hash mismatch.", {
                    "record_id": r_id,
                    "expected_previous": expected_prev,
                    "actual_previous": prev_hash
                }

            canonical = f"{r_id}|{prev_hash}|{action}|{entity_type}|{entity_id}|{details_json}|{created_at}"
            computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            if computed_hash != entry_hash:
                return False, idx, f"Data tampering detected at record ID {r_id}! Hash does not match content.", {
                    "record_id": r_id,
                    "computed_hash": computed_hash,
                    "stored_hash": entry_hash
                }
            expected_prev = entry_hash

        return True, len(rows), f"Audit chain verified successfully! All {len(rows)} records are cryptographically authentic and unaltered.", None
    finally:
        conn.close()

# ==================== DASHBOARD METRICS ====================

def get_dashboard_metrics():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Total events
        cur.execute("SELECT COUNT(*) FROM security_events")
        total_events = cur.fetchone()[0]

        # Active alerts (New or Investigating)
        cur.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('New', 'Investigating')")
        active_alerts = cur.fetchone()[0]

        # Critical active alerts
        cur.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('New', 'Investigating') AND severity = 'Critical'")
        critical_alerts = cur.fetchone()[0]

        # Total URL scans
        cur.execute("SELECT COUNT(*) FROM url_scans")
        total_url_scans = cur.fetchone()[0]

        # Suspicious URLs (score >= 50: High/Critical)
        cur.execute("SELECT COUNT(*) FROM url_scans WHERE score >= 50")
        suspicious_urls = cur.fetchone()[0]

        # Completed phishing awareness quizzes
        cur.execute("SELECT COUNT(*) FROM simulation_events")
        completed_quizzes = cur.fetchone()[0]

        # Recent incidents
        cur.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 5")
        recent_incidents = [dict(r) for r in cur.fetchall()]

        # Recent alerts
        cur.execute(
            """SELECT a.*, r.rule_code FROM alerts a
               JOIN detection_rules r ON a.rule_id = r.id
               ORDER BY a.last_seen DESC LIMIT 5"""
        )
        recent_alerts = [dict(r) for r in cur.fetchall()]

        # Events by type
        cur.execute("SELECT event_type, COUNT(*) as cnt FROM security_events GROUP BY event_type ORDER BY cnt DESC")
        events_by_type = [dict(r) for r in cur.fetchall()]

        # Events by outcome
        cur.execute("SELECT outcome, COUNT(*) as cnt FROM security_events GROUP BY outcome ORDER BY cnt DESC")
        events_by_outcome = [dict(r) for r in cur.fetchall()]

        return {
            "total_events": total_events,
            "active_alerts": active_alerts,
            "critical_alerts": critical_alerts,
            "total_url_scans": total_url_scans,
            "suspicious_urls": suspicious_urls,
            "completed_quizzes": completed_quizzes,
            "recent_incidents": recent_incidents,
            "recent_alerts": recent_alerts,
            "events_by_type": events_by_type,
            "events_by_outcome": events_by_outcome
        }
    finally:
        conn.close()
