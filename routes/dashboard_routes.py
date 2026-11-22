import json
from datetime import datetime, timezone
from io import BytesIO

from flask import Blueprint, render_template, jsonify, redirect, url_for, flash, send_file
from database.repositories import (
    get_dashboard_metrics,
    get_security_events,
    get_recent_url_scans,
    get_simulation_history,
)
from database.reset_data import reset_to_clean_state

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    metrics = get_dashboard_metrics()
    return render_template("dashboard.html", metrics=metrics)

@dashboard_bp.route("/api/dashboard/stats")
def api_dashboard_stats():
    metrics = get_dashboard_metrics()
    return jsonify(metrics)

@dashboard_bp.route("/dashboard/export")
def export_dashboard_data():
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": get_dashboard_metrics(),
        "security_events": get_security_events(limit=10000),
        "url_scans": get_recent_url_scans(limit=10000),
        "phishing_quiz_results": get_simulation_history(limit=10000),
    }
    report_file = BytesIO(json.dumps(report, indent=2).encode("utf-8"))
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return send_file(
        report_file,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"login_twin_security_report_{timestamp}.json",
    )

@dashboard_bp.route("/reset-database", methods=["POST"])
def reset_database_action():
    try:
        reset_to_clean_state()
        flash("Database successfully reset! All events, alerts, and scans have been cleared back to pristine state.", "info")
    except Exception as e:
        flash(f"Error resetting database: {str(e)}", "danger")
    return redirect(url_for("dashboard.index"))
