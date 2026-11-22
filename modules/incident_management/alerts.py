from database.repositories import (
    get_alerts,
    get_alert_by_id,
    update_alert_status,
    add_audit_log,
    create_incident
)

VALID_ALERT_STATUSES = {"New", "Investigating", "Resolved", "Closed"}

def list_alerts(status=None, severity=None, limit=50):
    return get_alerts(limit=limit, status=status, severity=severity)

def get_alert_details(alert_id):
    return get_alert_by_id(alert_id)

def set_alert_status(alert_id, new_status, actor_id=None):
    if new_status not in VALID_ALERT_STATUSES:
        raise ValueError(f"Invalid alert status '{new_status}'. Allowed: {VALID_ALERT_STATUSES}")
    
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise ValueError(f"Alert #{alert_id} not found.")

    old_status = alert["status"]
    update_alert_status(alert_id, new_status)
    
    add_audit_log(
        action="ALERT_STATUS_CHANGED",
        entity_type="ALERT",
        entity_id=alert_id,
        details={"old_status": old_status, "new_status": new_status},
        actor_id=actor_id
    )
    return True

def escalate_alert_to_new_incident(alert_id, custom_title=None, summary=None, actor_id=None):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise ValueError(f"Alert #{alert_id} not found.")

    title = custom_title or f"Incident: {alert['title']}"
    summary = summary or f"Escalated from Alert #{alert_id} ({alert['rule_name']}). {alert['description']}"
    
    incident_id = create_incident(
        title=title,
        severity=alert["severity"],
        summary=summary,
        alert_ids=[alert_id],
        actor_id=actor_id
    )

    add_audit_log(
        action="INCIDENT_ESCALATED",
        entity_type="INCIDENT",
        entity_id=incident_id,
        details={"alert_id": alert_id, "severity": alert["severity"]},
        actor_id=actor_id
    )
    return incident_id
