from database.repositories import (
    get_incidents,
    get_incident_by_id,
    create_incident,
    update_incident_status,
    add_incident_note,
    add_audit_log
)

ALLOWED_TRANSITIONS = {
    "New": ["Investigating", "Closed"],
    "Investigating": ["Resolved", "New"],
    "Resolved": ["Closed", "Investigating"],
    "Closed": ["Investigating"] # Reopen through explicit analyst action
}

def list_incidents(status=None):
    return get_incidents(status=status)

def get_incident_details(incident_id):
    return get_incident_by_id(incident_id)

def create_new_incident(title, severity, summary, alert_ids=None, actor_id=None):
    if not title or not summary:
        raise ValueError("Title and summary are required to initiate an incident.")
    
    incident_id = create_incident(
        title=title,
        severity=severity or "Medium",
        summary=summary,
        alert_ids=alert_ids or [],
        actor_id=actor_id
    )

    add_audit_log(
        action="INCIDENT_CREATED",
        entity_type="INCIDENT",
        entity_id=incident_id,
        details={"title": title, "severity": severity, "alerts": alert_ids or []},
        actor_id=actor_id
    )
    return incident_id

def transition_incident(incident_id, new_status, note="", actor_id=None):
    incident = get_incident_by_id(incident_id)
    if not incident:
        raise ValueError(f"Incident #{incident_id} does not exist.")

    current_status = incident["status"]
    allowed = ALLOWED_TRANSITIONS.get(current_status, [])
    if new_status not in allowed:
        raise ValueError(f"Invalid transition from '{current_status}' to '{new_status}'. Allowed: {', '.join(allowed)}")

    if new_status == "Resolved" and not note.strip():
        raise ValueError("Resolution note/mitigation summary is required when marking an incident Resolved.")

    success = update_incident_status(incident_id, new_status, note=note.strip(), actor_id=actor_id)
    if success:
        add_audit_log(
            action="INCIDENT_STATUS_CHANGE",
            entity_type="INCIDENT",
            entity_id=incident_id,
            details={"old_status": current_status, "new_status": new_status, "note": note},
            actor_id=actor_id
        )
    return success

def append_investigation_note(incident_id, note, actor_id=None):
    if not note or not note.strip():
        raise ValueError("Note content cannot be empty.")
    
    success = add_incident_note(incident_id, note.strip(), actor_id=actor_id)
    if success:
        add_audit_log(
            action="INCIDENT_NOTE_ADDED",
            entity_type="INCIDENT",
            entity_id=incident_id,
            details={"note_snippet": note[:80]},
            actor_id=actor_id
        )
    return success
