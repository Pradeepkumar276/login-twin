from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from modules.phishing_lab.awareness import evaluate_phishing_submission
from database.repositories import get_active_scenarios, get_scenario_by_code, get_simulation_history

phishing_bp = Blueprint("phishing_lab", __name__)

@phishing_bp.route("/phishing-lab")
@phishing_bp.route("/phishing-quiz")
def phishing_lab_index():
    scenarios = get_active_scenarios()
    history = get_simulation_history(limit=10)
    return render_template("phishing_lab.html", scenarios=scenarios, history=history, active_scenario=None)

@phishing_bp.route("/phishing-lab/<string:code>")
@phishing_bp.route("/phishing-quiz/<string:code>")
def open_scenario(code):
    scenarios = get_active_scenarios()
    scenario = get_scenario_by_code(code)
    if not scenario:
        flash(f"Scenario '{code}' not found.", "warning")
        return redirect(url_for("phishing_lab.phishing_lab_index"))
    history = get_simulation_history(limit=10)
    return render_template("phishing_lab.html", scenarios=scenarios, history=history, active_scenario=scenario)

@phishing_bp.route("/phishing-lab/<string:code>/submit", methods=["POST"])
@phishing_bp.route("/phishing-quiz/<string:code>/submit", methods=["POST"])
def submit_scenario_quiz(code):
    scenario = get_scenario_by_code(code)
    if not scenario:
        flash(f"Scenario '{code}' not found.", "danger")
        return redirect(url_for("phishing_lab.phishing_lab_index"))

    selected_indicators = request.form.getlist("indicators")
    selected_action = request.form.get("safe_action")

    # Safe validation: verify NO password fields were included
    for forbidden_key in ["password", "passwd", "pin", "credential", "pass"]:
        if forbidden_key in request.form:
            # Drop and ignore
            pass

    try:
        evaluation = evaluate_phishing_submission(
            scenario_code=code,
            selected_indicator_ids=selected_indicators,
            selected_action_id=selected_action
        )
        scenarios = get_active_scenarios()
        history = get_simulation_history(limit=10)
        return render_template(
            "phishing_lab.html",
            scenarios=scenarios,
            history=history,
            active_scenario=scenario,
            evaluation=evaluation
        )
    except Exception as e:
        flash(f"Error evaluating submission: {str(e)}", "danger")
        return redirect(url_for("phishing_lab.open_scenario", code=code))

@phishing_bp.route("/api/phishing/<string:code>/submit", methods=["POST"])
def api_submit_phishing(code):
    data = request.get_json(silent=True) or {}
    indicators = data.get("indicators", [])
    action = data.get("safe_action")
    try:
        res = evaluate_phishing_submission(code, indicators, action)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
