from flask import Blueprint, render_template, request, jsonify
from modules.chatbot.explainer import answer_query

chatbot_bp = Blueprint("chatbot", __name__)

@chatbot_bp.route("/chatbot")
def chatbot_page():
    return render_template("chatbot.html")

@chatbot_bp.route("/api/chatbot/ask", methods=["POST"])
def api_chatbot_ask():
    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()
    if not query:
        query = request.form.get("query", "").strip()

    response = answer_query(query)
    return jsonify(response)
