from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from modules.incident_management.incidents import (
    list_incidents,
    get_incident_details,
    create_new_incident,
    transition_incident,
    append_investigation_note
)
from modules.incident_management.audit import get_audit_history, verify_system_audit_integrity
from modules.correlation.correlation_engine import run_correlation_engine
from database.repositories import get_correlations, get_correlation_by_id, get_alerts

incident_bp = Blueprint("incidents", __name__)

# ==================== INCIDENTS ====================

@incident_bp.route("/incidents")
def incidents_page():
    status_filter = request.args.get("status", "").strip() or None
    incidents_list = list_incidents(status=status_filter)
    available_alerts = get_alerts(limit=50, status="New")
    return render_template(
        "incidents.html",
        incidents=incidents_list,
        current_status=status_filter,
        available_alerts=available_alerts,
        active_incident=None
    )

@incident_bp.route("/incidents/<int:incident_id>")
def incident_detail_page(incident_id):
    incident = get_incident_details(incident_id)
    if not incident:
        flash(f"Incident #{incident_id} not found.", "warning")
        return redirect(url_for("incidents.incidents_page"))
    
    status_filter = request.args.get("status", "").strip() or None
    incidents_list = list_incidents(status=status_filter)
    available_alerts = get_alerts(limit=50)
    return render_template(
        "incidents.html",
        incidents=incidents_list,
        current_status=status_filter,
        available_alerts=available_alerts,
        active_incident=incident
    )

@incident_bp.route("/incidents/new", methods=["POST"])
def create_incident_action():
    title = request.form.get("title", "").strip()
    severity = request.form.get("severity", "Medium")
    summary = request.form.get("summary", "").strip()
    alert_ids = request.form.getlist("alert_ids")
    int_alert_ids = [int(a) for a in alert_ids if a.isdigit()]

    try:
        inc_id = create_new_incident(title, severity, summary, alert_ids=int_alert_ids)
        flash(f"Incident #{inc_id} successfully registered.", "success")
        return redirect(url_for("incidents.incident_detail_page", incident_id=inc_id))
    except Exception as e:
        flash(f"Error creating incident: {str(e)}", "danger")
        return redirect(url_for("incidents.incidents_page"))

@incident_bp.route("/incidents/<int:incident_id>/status", methods=["POST"])
def update_incident_status_action(incident_id):
    new_status = request.form.get("status")
    note = request.form.get("note", "").strip()
    try:
        transition_incident(incident_id, new_status, note=note)
        flash(f"Incident #{incident_id} transition to '{new_status}' recorded.", "success")
    except Exception as e:
        flash(f"Status transition failed: {str(e)}", "danger")
    return redirect(url_for("incidents.incident_detail_page", incident_id=incident_id))

@incident_bp.route("/incidents/<int:incident_id>/notes", methods=["POST"])
def add_note_action(incident_id):
    note = request.form.get("note", "").strip()
    try:
        append_investigation_note(incident_id, note)
        flash("Analyst investigation note recorded in incident history.", "success")
    except Exception as e:
        flash(f"Failed to record note: {str(e)}", "danger")
    return redirect(url_for("incidents.incident_detail_page", incident_id=incident_id))

# ==================== CORRELATIONS ====================

@incident_bp.route("/correlations")
def correlations_page():
    correlations = get_correlations(limit=50)
    return render_template("correlations.html", correlations=correlations, active_correlation=None)

@incident_bp.route("/correlations/<int:correlation_id>")
def correlation_detail_page(correlation_id):
    correlations = get_correlations(limit=50)
    target = get_correlation_by_id(correlation_id)
    if not target:
        flash(f"Correlation #{correlation_id} not found.", "warning")
        return redirect(url_for("incidents.correlations_page"))
    return render_template("correlations.html", correlations=correlations, active_correlation=target)

@incident_bp.route("/correlations/run", methods=["POST"])
def run_correlations_action():
    new_corrs = run_correlation_engine()
    flash(f"Correlation engine completed. Created {len(new_corrs)} new correlated incident group(s).", "info")
    return redirect(url_for("incidents.correlations_page"))

# ==================== AUDIT LOG & INTEGRITY ====================

@incident_bp.route("/audit")
def audit_page():
    logs = get_audit_history(limit=100)
    integrity = verify_system_audit_integrity()
    return render_template("audit.html", logs=logs, integrity=integrity)

@incident_bp.route("/audit/verify", methods=["POST"])
def verify_audit_action():
    integrity = verify_system_audit_integrity()
    if integrity["valid"]:
        flash(integrity["message"], "success")
    else:
        flash(f"INTEGRITY ALERT: {integrity['message']}", "danger")
    return redirect(url_for("incidents.audit_page"))
