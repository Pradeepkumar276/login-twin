from flask import Flask, render_template
import os
import json
from config import Config
from database.db import init_db
from routes.dashboard_routes import dashboard_bp
from routes.url_routes import url_bp
from routes.phishing_routes import phishing_bp
from routes.soc_routes import soc_bp
from routes.alert_routes import alert_bp
from routes.incident_routes import incident_bp
from routes.chatbot_routes import chatbot_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Database Schema & Seed Data
    with app.app_context():
        init_db(app.config["DATABASE_PATH"])

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(url_bp)
    app.register_blueprint(phishing_bp)
    app.register_blueprint(soc_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(chatbot_bp)

    # Custom Jinja Template Filters
    @app.template_filter("pretty_json")
    def pretty_json(value):
        if not value:
            return "{}"
        if isinstance(value, str):
            try:
                val = json.loads(value)
                return json.dumps(val, indent=2)
            except Exception:
                return value
        try:
            return json.dumps(value, indent=2)
        except Exception:
            return str(value)

    @app.template_filter("time_ago")
    def time_ago(iso_str):
        if not iso_str:
            return "N/A"
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            diff = now - dt
            seconds = int(diff.total_seconds())
            if seconds < 60:
                return f"{seconds}s ago"
            minutes = seconds // 60
            if minutes < 60:
                return f"{minutes}m ago"
            hours = minutes // 60
            if hours < 24:
                return f"{hours}h ago"
            days = hours // 24
            return f"{days}d ago"
        except Exception:
            return iso_str[:19].replace("T", " ")

    # Safe Error Handling: Do not expose raw stack traces in browser
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("base.html", error_title="404 - Resource Not Found", error_message="The requested endpoint or resource does not exist."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("base.html", error_title="500 - Server Error", error_message="An internal server error occurred. Technical details have been safely logged server-side."), 500

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
