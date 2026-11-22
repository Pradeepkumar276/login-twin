from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from database.repositories import get_security_events, get_event_by_id
from modules.soc_monitor.log_ingestion import ingest_json_events, generate_demo_events, IngestionError
from modules.soc_monitor.detection_engine import run_all_detection_rules

soc_bp = Blueprint("soc_monitor", __name__)

@soc_bp.route("/soc/events")
def soc_events_page():
    filters = {
        "event_type": request.args.get("event_type", "").strip() or None,
        "outcome": request.args.get("outcome", "").strip() or None,
        "source_ip": request.args.get("source_ip", "").strip() or None,
        "account_id": request.args.get("account_id", "").strip() or None,
        "source": request.args.get("source", "").strip() or None
    }
    # Clean empty filters
    active_filters = {k: v for k, v in filters.items() if v}
    events = get_security_events(limit=100, filters=active_filters)
    return render_template("soc.html", events=events, current_filters=filters)

@soc_bp.route("/soc/events/<int:event_id>")
def get_event_json(event_id):
    ev = get_event_by_id(event_id)
    if not ev:
        return jsonify({"error": "Event not found"}), 404
    return jsonify(ev)

@soc_bp.route("/soc/ingest", methods=["POST"])
def ingest_events_action():
    source_label = request.form.get("source_label", "uploaded_file").strip() or "uploaded_file"
    raw_json = None

    if "log_file" in request.files and request.files["log_file"].filename != "":
        file_obj = request.files["log_file"]
        raw_json = file_obj.read().decode("utf-8")
    elif "json_payload" in request.form and request.form["json_payload"].strip() != "":
        raw_json = request.form["json_payload"].strip()

    if not raw_json:
        flash("No JSON file or payload was provided.", "warning")
        return redirect(url_for("soc_monitor.soc_events_page"))

    try:
        result = ingest_json_events(raw_json, source=source_label, auto_detect=True)
        flash(
            f"Successfully ingested {result['ingested_count']} security events. "
            f"Triggered/updated {result['alerts_triggered']} alerts.",
            "success"
        )
    except IngestionError as err:
        flash(f"Ingestion rejected: {str(err)}", "danger")
    except Exception as err:
        flash(f"Unexpected error during ingestion: {str(err)}", "danger")

    return redirect(url_for("soc_monitor.soc_events_page"))

@soc_bp.route("/soc/demo-events", methods=["POST"])
def demo_events_action():
    scenario = request.form.get("scenario", "brute_force")
    try:
        result = generate_demo_events(scenario_type=scenario)
        flash(
            f"Generated and ingested {result['ingested_count']} demo events for scenario '{scenario}'. "
            f"{result['alerts_triggered']} alerts triggered or updated.",
            "info"
        )
    except Exception as err:
        flash(f"Error generating demo scenario: {str(err)}", "danger")

    return redirect(url_for("soc_monitor.soc_events_page"))

@soc_bp.route("/soc/run-detections", methods=["POST"])
def run_detections_action():
    alerts = run_all_detection_rules()
    flash(f"Detection engine executed. {len(alerts)} alerts generated or updated.", "info")
    return redirect(url_for("soc_monitor.soc_events_page"))

@soc_bp.route("/api/soc/ingest", methods=["POST"])
def api_ingest_events():
    data = request.get_json(silent=True)
    if data is None:
        data = request.form.get("json_payload")
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400
    try:
        result = ingest_json_events(data, source="api_call", auto_detect=True)
        return jsonify(result)
    except IngestionError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        return jsonify({"error": str(e)}), 500
