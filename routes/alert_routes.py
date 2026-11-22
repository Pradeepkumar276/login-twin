from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from modules.incident_management.alerts import (
    list_alerts,
    get_alert_details,
    set_alert_status,
    escalate_alert_to_new_incident
)
from database.repositories import get_detection_rules

alert_bp = Blueprint("alerts", __name__)

@alert_bp.route("/alerts")
def alerts_page():
    status_filter = request.args.get("status", "").strip() or None
    severity_filter = request.args.get("severity", "").strip() or None
    alerts_list = list_alerts(status=status_filter, severity=severity_filter, limit=100)
    rules = get_detection_rules()
    return render_template(
        "alerts.html",
        alerts=alerts_list,
        rules=rules,
        current_status=status_filter,
        current_severity=severity_filter,
        active_alert=None
    )

@alert_bp.route("/alerts/<int:alert_id>")
def alert_detail_page(alert_id):
    alert = get_alert_details(alert_id)
    if not alert:
        flash(f"Alert #{alert_id} not found.", "warning")
        return redirect(url_for("alerts.alerts_page"))
    
    status_filter = request.args.get("status", "").strip() or None
    severity_filter = request.args.get("severity", "").strip() or None
    alerts_list = list_alerts(status=status_filter, severity=severity_filter, limit=100)
    rules = get_detection_rules()
    return render_template(
        "alerts.html",
        alerts=alerts_list,
        rules=rules,
        current_status=status_filter,
        current_severity=severity_filter,
        active_alert=alert
    )

@alert_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_status_action(alert_id):
    new_status = request.form.get("status")
    try:
        set_alert_status(alert_id, new_status)
        flash(f"Alert #{alert_id} status updated to '{new_status}'.", "success")
    except Exception as e:
        flash(f"Failed to update status: {str(e)}", "danger")
    return redirect(url_for("alerts.alert_detail_page", alert_id=alert_id))

@alert_bp.route("/alerts/<int:alert_id>/escalate", methods=["POST"])
def escalate_action(alert_id):
    title = request.form.get("title")
    summary = request.form.get("summary")
    try:
        incident_id = escalate_alert_to_new_incident(alert_id, custom_title=title, summary=summary)
        flash(f"Successfully escalated Alert #{alert_id} to Incident #{incident_id}!", "success")
        return redirect(url_for("incidents.incident_detail_page", incident_id=incident_id))
    except Exception as e:
        flash(f"Escalation failed: {str(e)}", "danger")
        return redirect(url_for("alerts.alert_detail_page", alert_id=alert_id))
