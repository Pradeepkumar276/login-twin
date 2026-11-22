from datetime import datetime
from config import Config
from database.db import get_db_connection
from database.repositories import create_correlation, add_audit_log

def parse_iso_epoch(iso_str):
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0

def run_correlation_engine(time_window_seconds=None):
    """
    Correlates security alerts and related events sharing an investigative pivot
    (e.g., shared source IP across different attack types or targeted accounts).
    Produces explainable correlation records with attached evidence links.
    """
    if time_window_seconds is None:
        time_window_seconds = Config.CORRELATION_WINDOW_SECONDS

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Fetch open or recent alerts with their evidence events
        cur.execute(
            """SELECT a.id as alert_id, a.rule_id, a.title, a.severity, a.first_seen, a.last_seen,
                      r.rule_code, r.name as rule_name
               FROM alerts a
               JOIN detection_rules r ON a.rule_id = r.id
               ORDER BY a.first_seen ASC"""
        )
        alerts = [dict(r) for r in cur.fetchall()]

        # Fetch alert to events mapping
        cur.execute(
            """SELECT ae.alert_id, e.id as event_id, e.event_time, e.source_ip, e.account_id, e.event_type, e.outcome
               FROM alert_events ae
               JOIN security_events e ON ae.event_id = e.id
               ORDER BY e.event_time ASC"""
        )
        alert_events = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    if not alerts or not alert_events:
        return []

    # Map alert_id -> events
    alert_to_events = {}
    for row in alert_events:
        alert_to_events.setdefault(row["alert_id"], []).append(row)

    # 1. Pivot by source IP
    ip_to_alerts = {}
    for alt in alerts:
        a_id = alt["alert_id"]
        evs = alert_to_events.get(a_id, [])
        ips = set(e["source_ip"] for e in evs if e["source_ip"])
        for ip in ips:
            ip_to_alerts.setdefault(ip, []).append(alt)

    new_correlations = []

    for source_ip, matched_alerts in ip_to_alerts.items():
        # De-duplicate alerts
        unique_alerts = {a["alert_id"]: a for a in matched_alerts}.values()
        if len(unique_alerts) >= 2:
            alert_ids = [a["alert_id"] for a in unique_alerts]
            rule_codes = list(set(a["rule_code"] for a in unique_alerts))
            severities = list(set(a["severity"] for a in unique_alerts))
            
            # Gather all evidence event IDs for these alerts
            member_event_ids = []
            event_types = set()
            timestamps = []
            for aid in alert_ids:
                for ev in alert_to_events.get(aid, []):
                    member_event_ids.append(ev["event_id"])
                    event_types.add(ev["event_type"])
                    timestamps.append(parse_iso_epoch(ev["event_time"]))

            member_event_ids = list(set(member_event_ids))
            if not timestamps:
                continue

            min_time = min(timestamps)
            max_time = max(timestamps)

            # Check if activities fall within the correlation window
            if (max_time - min_time) <= (time_window_seconds * 2): # allow reasonable multi-stage burst
                start_iso = datetime.fromtimestamp(min_time).isoformat()
                end_iso = datetime.fromtimestamp(max_time).isoformat()
                
                # Check if correlation already exists for this key and time
                conn2 = get_db_connection()
                try:
                    cur2 = conn2.cursor()
                    cur2.execute(
                        "SELECT id FROM correlations WHERE correlation_key = ? AND correlation_type = 'shared_ip'",
                        (source_ip,)
                    )
                    existing = cur2.fetchone()
                finally:
                    conn2.close()

                if not existing:
                    explanation = (
                        f"Correlated multi-rule threat pattern from source IP {source_ip}. "
                        f"Linked {len(alert_ids)} distinct alert(s) spanning rule(s) {', '.join(rule_codes)} "
                        f"and event type(s) {', '.join(event_types)}. "
                        f"Note: Public IP attribution may represent NAT or proxy gateways; verify independently."
                    )

                    cid = create_correlation(
                        correlation_type="shared_ip",
                        correlation_key=source_ip,
                        explanation=explanation,
                        start_time=start_iso,
                        end_time=end_iso,
                        event_ids=member_event_ids,
                        alert_ids=alert_ids
                    )
                    new_correlations.append({
                        "id": cid,
                        "type": "shared_ip",
                        "key": source_ip,
                        "alerts_count": len(alert_ids),
                        "events_count": len(member_event_ids)
                    })
                    add_audit_log(
                        action="CORRELATION_FORMED",
                        entity_type="CORRELATION",
                        entity_id=cid,
                        details={"key": source_ip, "rules": rule_codes, "alerts": alert_ids}
                    )

    return new_correlations
