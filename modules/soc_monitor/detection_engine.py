import hashlib
from datetime import datetime, timezone
from database.db import get_db_connection
from database.repositories import (
    get_detection_rules,
    get_detection_rule_by_code,
    save_or_update_alert,
    add_audit_log
)
from modules.soc_monitor.rules import RULE_DEFINITIONS

def parse_iso_to_epoch(iso_str):
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0

def run_all_detection_rules():
    """
    Executes DET-001 through DET-005 over stored security events.
    Deterministic sliding window logic ensures consistent detection for both
    live streams and historic/sample JSON test cases.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Fetch all events ordered by time
        cur.execute("SELECT * FROM security_events ORDER BY event_time ASC, id ASC")
        all_events = [dict(r) for r in cur.fetchall()]
        
        # Fetch rule metadata from DB
        cur.execute("SELECT id, rule_code, severity, enabled FROM detection_rules")
        db_rules = {r["rule_code"]: dict(r) for r in cur.fetchall()}
    finally:
        conn.close()

    if not all_events:
        return []

    generated_alerts = []

    # ------------------ DET-001: Brute Force ------------------
    rule_01 = db_rules.get("DET-001")
    if rule_01 and rule_01.get("enabled", 1):
        window_sec = RULE_DEFINITIONS["DET-001"]["window_seconds"]
        threshold = RULE_DEFINITIONS["DET-001"]["threshold"]
        
        # Partition login failures by account_id
        account_failures = {}
        for e in all_events:
            if e["event_type"] == "login" and e["outcome"] == "failure" and e["account_id"]:
                account_failures.setdefault(e["account_id"], []).append(e)

        for account_id, events in account_failures.items():
            # Sliding window check
            n = len(events)
            i = 0
            while i < n:
                start_ts = parse_iso_to_epoch(events[i]["event_time"])
                window_events = [events[i]]
                j = i + 1
                while j < n:
                    next_ts = parse_iso_to_epoch(events[j]["event_time"])
                    if next_ts - start_ts <= window_sec:
                        window_events.append(events[j])
                        j += 1
                    else:
                        break
                
                if len(window_events) >= threshold:
                    event_ids = [ev["id"] for ev in window_events]
                    source_ips = list(set(ev["source_ip"] for ev in window_events if ev["source_ip"]))
                    first_time = window_events[0]["event_time"]
                    last_time = window_events[-1]["event_time"]
                    
                    # Stable fingerprint based on rule, target, and first event time window
                    time_bucket = int(start_ts // window_sec)
                    fp = hashlib.sha256(f"DET-001:{account_id}:{time_bucket}".encode()).hexdigest()[:24]
                    
                    title = f"Brute Force Detected on Account '{account_id}'"
                    description = (
                        f"Detected {len(window_events)} consecutive login failures for account '{account_id}' "
                        f"within {window_sec}s window. Source IP(s): {', '.join(source_ips) or 'Unknown'}. "
                        f"Time range: {first_time} to {last_time}."
                    )
                    
                    alert_id = save_or_update_alert(
                        fingerprint=fp,
                        rule_id=rule_01["id"],
                        severity=rule_01["severity"],
                        title=title,
                        description=description,
                        event_ids=event_ids,
                        confidence=85
                    )
                    generated_alerts.append({
                        "alert_id": alert_id,
                        "rule_code": "DET-001",
                        "title": title,
                        "event_count": len(window_events),
                        "evidence_ids": event_ids
                    })
                    add_audit_log(
                        action="ALERT_TRIGGERED",
                        entity_type="ALERT",
                        entity_id=alert_id,
                        details={"rule": "DET-001", "account_id": account_id, "events": len(window_events)}
                    )
                    i = j # Advance past this burst
                else:
                    i += 1

    # ------------------ DET-002: Password Spraying ------------------
    rule_02 = db_rules.get("DET-002")
    if rule_02 and rule_02.get("enabled", 1):
        window_sec = RULE_DEFINITIONS["DET-002"]["window_seconds"]
        threshold = RULE_DEFINITIONS["DET-002"]["threshold"]

        # Partition login failures by source_ip
        ip_failures = {}
        for e in all_events:
            if e["event_type"] == "login" and e["outcome"] == "failure" and e["source_ip"] and e["account_id"]:
                ip_failures.setdefault(e["source_ip"], []).append(e)

        for source_ip, events in ip_failures.items():
            n = len(events)
            i = 0
            while i < n:
                start_ts = parse_iso_to_epoch(events[i]["event_time"])
                window_events = [events[i]]
                j = i + 1
                while j < n:
                    next_ts = parse_iso_to_epoch(events[j]["event_time"])
                    if next_ts - start_ts <= window_sec:
                        window_events.append(events[j])
                        j += 1
                    else:
                        break

                distinct_accounts = set(ev["account_id"] for ev in window_events if ev["account_id"])
                if len(distinct_accounts) >= threshold:
                    event_ids = [ev["id"] for ev in window_events]
                    first_time = window_events[0]["event_time"]
                    last_time = window_events[-1]["event_time"]
                    
                    time_bucket = int(start_ts // window_sec)
                    fp = hashlib.sha256(f"DET-002:{source_ip}:{time_bucket}".encode()).hexdigest()[:24]

                    title = f"Password Spraying Detected from Source IP {source_ip}"
                    description = (
                        f"Detected single source IP {source_ip} attempting login against {len(distinct_accounts)} "
                        f"distinct accounts ({', '.join(sorted(list(distinct_accounts))[:5])}...) "
                        f"within {window_sec}s window. Time range: {first_time} to {last_time}."
                    )

                    alert_id = save_or_update_alert(
                        fingerprint=fp,
                        rule_id=rule_02["id"],
                        severity=rule_02["severity"],
                        title=title,
                        description=description,
                        event_ids=event_ids,
                        confidence=90
                    )
                    generated_alerts.append({
                        "alert_id": alert_id,
                        "rule_code": "DET-002",
                        "title": title,
                        "event_count": len(window_events),
                        "evidence_ids": event_ids
                    })
                    add_audit_log(
                        action="ALERT_TRIGGERED",
                        entity_type="ALERT",
                        entity_id=alert_id,
                        details={"rule": "DET-002", "source_ip": source_ip, "distinct_accounts": len(distinct_accounts)}
                    )
                    i = j
                else:
                    i += 1

    # ------------------ DET-003: Suspicious IP Activity Burst ------------------
    rule_03 = db_rules.get("DET-003")
    if rule_03 and rule_03.get("enabled", 1):
        window_sec = RULE_DEFINITIONS["DET-003"]["window_seconds"]
        threshold = RULE_DEFINITIONS["DET-003"]["threshold"]

        suspicious_by_ip = {}
        for e in all_events:
            if e["source_ip"] and e["outcome"] in ("failure", "denied", "invalid"):
                suspicious_by_ip.setdefault(e["source_ip"], []).append(e)

        for source_ip, events in suspicious_by_ip.items():
            n = len(events)
            i = 0
            while i < n:
                start_ts = parse_iso_to_epoch(events[i]["event_time"])
                window_events = [events[i]]
                j = i + 1
                while j < n:
                    next_ts = parse_iso_to_epoch(events[j]["event_time"])
                    if next_ts - start_ts <= window_sec:
                        window_events.append(events[j])
                        j += 1
                    else:
                        break

                if len(window_events) >= threshold:
                    event_ids = [ev["id"] for ev in window_events]
                    first_time = window_events[0]["event_time"]
                    last_time = window_events[-1]["event_time"]
                    
                    time_bucket = int(start_ts // window_sec)
                    fp = hashlib.sha256(f"DET-003:{source_ip}:{time_bucket}".encode()).hexdigest()[:24]

                    title = f"High Security Anomaly Rate from Source IP {source_ip}"
                    description = (
                        f"Detected {len(window_events)} failed, denied or invalid security events from IP {source_ip} "
                        f"within {window_sec}s. Exceeded threshold of {threshold} events."
                    )

                    alert_id = save_or_update_alert(
                        fingerprint=fp,
                        rule_id=rule_03["id"],
                        severity=rule_03["severity"],
                        title=title,
                        description=description,
                        event_ids=event_ids,
                        confidence=75
                    )
                    generated_alerts.append({
                        "alert_id": alert_id,
                        "rule_code": "DET-003",
                        "title": title,
                        "event_count": len(window_events),
                        "evidence_ids": event_ids
                    })
                    add_audit_log(
                        action="ALERT_TRIGGERED",
                        entity_type="ALERT",
                        entity_id=alert_id,
                        details={"rule": "DET-003", "source_ip": source_ip, "event_count": len(window_events)}
                    )
                    i = j
                else:
                    i += 1

    # ------------------ DET-004: Repeated Unauthorized Access ------------------
    rule_04 = db_rules.get("DET-004")
    if rule_04 and rule_04.get("enabled", 1):
        window_sec = RULE_DEFINITIONS["DET-004"]["window_seconds"]
        threshold = RULE_DEFINITIONS["DET-004"]["threshold"]

        denied_by_target = {}
        for e in all_events:
            if e["event_type"] == "access_denied" or e["outcome"] == "denied":
                key = e["source_ip"] or e["account_id"]
                if key:
                    denied_by_target.setdefault(key, []).append(e)

        for key, events in denied_by_target.items():
            n = len(events)
            i = 0
            while i < n:
                start_ts = parse_iso_to_epoch(events[i]["event_time"])
                window_events = [events[i]]
                j = i + 1
                while j < n:
                    next_ts = parse_iso_to_epoch(events[j]["event_time"])
                    if next_ts - start_ts <= window_sec:
                        window_events.append(events[j])
                        j += 1
                    else:
                        break

                if len(window_events) >= threshold:
                    event_ids = [ev["id"] for ev in window_events]
                    resources = list(set(ev["resource"] for ev in window_events if ev["resource"]))
                    time_bucket = int(start_ts // window_sec)
                    fp = hashlib.sha256(f"DET-004:{key}:{time_bucket}".encode()).hexdigest()[:24]

                    title = f"Repeated Access Denied Violations from '{key}'"
                    description = (
                        f"Detected {len(window_events)} access denied authorization failures targeting resource(s): "
                        f"{', '.join(resources) or 'unspecified'} within {window_sec}s."
                    )

                    alert_id = save_or_update_alert(
                        fingerprint=fp,
                        rule_id=rule_04["id"],
                        severity=rule_04["severity"],
                        title=title,
                        description=description,
                        event_ids=event_ids,
                        confidence=80
                    )
                    generated_alerts.append({
                        "alert_id": alert_id,
                        "rule_code": "DET-004",
                        "title": title,
                        "event_count": len(window_events),
                        "evidence_ids": event_ids
                    })
                    add_audit_log(
                        action="ALERT_TRIGGERED",
                        entity_type="ALERT",
                        entity_id=alert_id,
                        details={"rule": "DET-004", "target": key, "event_count": len(window_events)}
                    )
                    i = j
                else:
                    i += 1

    # ------------------ DET-005: Abnormal Request Activity ------------------
    rule_05 = db_rules.get("DET-005")
    if rule_05 and rule_05.get("enabled", 1):
        window_sec = RULE_DEFINITIONS["DET-005"]["window_seconds"]
        threshold = RULE_DEFINITIONS["DET-005"]["threshold"]

        invalid_by_ip = {}
        for e in all_events:
            if e["source_ip"] and (e["event_type"] == "request_invalid" or e["outcome"] == "invalid"):
                invalid_by_ip.setdefault(e["source_ip"], []).append(e)

        for source_ip, events in invalid_by_ip.items():
            n = len(events)
            i = 0
            while i < n:
                start_ts = parse_iso_to_epoch(events[i]["event_time"])
                window_events = [events[i]]
                j = i + 1
                while j < n:
                    next_ts = parse_iso_to_epoch(events[j]["event_time"])
                    if next_ts - start_ts <= window_sec:
                        window_events.append(events[j])
                        j += 1
                    else:
                        break

                if len(window_events) >= threshold:
                    event_ids = [ev["id"] for ev in window_events]
                    time_bucket = int(start_ts // window_sec)
                    fp = hashlib.sha256(f"DET-005:{source_ip}:{time_bucket}".encode()).hexdigest()[:24]

                    title = f"Abnormal Invalid Request Burst from {source_ip}"
                    description = (
                        f"Detected {len(window_events)} malformed or invalid requests from IP {source_ip} "
                        f"within {window_sec}s window. Exceeded threshold of {threshold}."
                    )

                    alert_id = save_or_update_alert(
                        fingerprint=fp,
                        rule_id=rule_05["id"],
                        severity=rule_05["severity"],
                        title=title,
                        description=description,
                        event_ids=event_ids,
                        confidence=70
                    )
                    generated_alerts.append({
                        "alert_id": alert_id,
                        "rule_code": "DET-005",
                        "title": title,
                        "event_count": len(window_events),
                        "evidence_ids": event_ids
                    })
                    add_audit_log(
                        action="ALERT_TRIGGERED",
                        entity_type="ALERT",
                        entity_id=alert_id,
                        details={"rule": "DET-005", "source_ip": source_ip, "event_count": len(window_events)}
                    )
                    i = j
                else:
                    i += 1

    return generated_alerts
