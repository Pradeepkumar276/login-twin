from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from modules.url_analyzer.analyzer import analyze_url, URLAnalysisError
from database.repositories import get_recent_url_scans, get_url_scan_by_id

url_bp = Blueprint("url_analyzer", __name__)

@url_bp.route("/url-analyzer", methods=["GET", "POST"])
def url_analyzer_page():
    recent_scans = get_recent_url_scans(limit=15)
    scan_result = None
    error_message = None

    if request.method == "POST":
        target_url = request.form.get("url", "").strip()
        if not target_url:
            error_message = "Please enter a valid URL to analyze."
        else:
            try:
                scan_result = analyze_url(target_url, save_to_db=True)
                # Refresh recent scans
                recent_scans = get_recent_url_scans(limit=15)
            except URLAnalysisError as err:
                error_message = str(err)
            except Exception as e:
                error_message = f"Analysis error: {str(e)}"

    return render_template(
        "url_analyzer.html",
        scan_result=scan_result,
        recent_scans=recent_scans,
        error_message=error_message
    )

@url_bp.route("/url-scans/<int:scan_id>")
def view_saved_scan(scan_id):
    scan = get_url_scan_by_id(scan_id)
    if not scan:
        flash(f"Scan ID #{scan_id} not found.", "warning")
        return redirect(url_for("url_analyzer.url_analyzer_page"))
    recent_scans = get_recent_url_scans(limit=15)
    return render_template("url_analyzer.html", scan_result=scan, recent_scans=recent_scans, is_historical=True)

@url_bp.route("/api/url/analyze", methods=["POST"])
def api_analyze_url():
    data = request.get_json(silent=True) or {}
    url_str = data.get("url") or request.form.get("url")
    if not url_str:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    try:
        res = analyze_url(url_str, save_to_db=True)
        return jsonify(res)
    except URLAnalysisError as err:
        return jsonify({"error": str(err)}), 422
    except Exception as err:
        return jsonify({"error": str(err)}), 500
