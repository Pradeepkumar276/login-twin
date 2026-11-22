from database.repositories import get_scenario_by_code, save_simulation_event, get_active_scenarios

def evaluate_phishing_submission(scenario_code, selected_indicator_ids, selected_action_id, user_id=None):
    """
    Evaluates participant responses in the safe phishing awareness lab.
    Does NOT accept, handle, or persist credentials.
    Computes objective awareness score, detailed feedback on indicators, and stores event.
    """
    scenario = get_scenario_by_code(scenario_code)
    if not scenario:
        raise ValueError(f"Scenario with code '{scenario_code}' not found.")

    correct_indicators = set(scenario.get("correct_indicator_ids", []))
    selected_indicators = set(selected_indicator_ids or [])
    
    # Calculate indicator identification score
    true_positives = len(selected_indicators.intersection(correct_indicators))
    false_positives = len(selected_indicators - correct_indicators)
    missed_indicators = len(correct_indicators - selected_indicators)

    total_correct_available = max(len(correct_indicators), 1)
    indicator_score_fraction = max(0.0, (true_positives - (false_positives * 0.5))) / total_correct_available
    indicator_score = round(min(1.0, indicator_score_fraction) * 60) # up to 60 points

    # Calculate safe action selection score
    correct_action_id = scenario.get("correct_action_id")
    action_correct = (selected_action_id == correct_action_id)
    action_score = 40 if action_correct else 0 # up to 40 points

    total_score = indicator_score + action_score

    # Indicator breakdown for educational feedback
    indicator_feedback = []
    for ind in scenario.get("available_indicators", []):
        iid = ind["id"]
        is_true_indicator = iid in correct_indicators
        was_selected = iid in selected_indicators
        
        if was_selected and is_true_indicator:
            status = "correct_identified"
            comment = f"Correctly flagged: '{ind['label']}' is a clear phishing signal."
        elif was_selected and not is_true_indicator:
            status = "false_positive"
            comment = f"Incorrectly flagged: '{ind['label']}' is not a suspicious indicator in this scenario."
        elif not was_selected and is_true_indicator:
            status = "missed"
            comment = f"Missed clue: '{ind['label']}' was a key indicator of deceit."
        else:
            status = "correct_ignored"
            comment = f"Correctly ignored: '{ind['label']}' was a benign attribute."

        indicator_feedback.append({
            "id": iid,
            "label": ind["label"],
            "is_suspicious": is_true_indicator,
            "was_selected": was_selected,
            "status": status,
            "comment": comment
        })

    # Action feedback
    selected_action_obj = None
    for act in scenario.get("safe_action_options", []):
        if act["id"] == selected_action_id:
            selected_action_obj = act
            break

    action_feedback = {
        "selected_action_id": selected_action_id,
        "selected_action_label": selected_action_obj["label"] if selected_action_obj else "No action selected",
        "is_safe": action_correct,
        "correct_action_id": correct_action_id,
        "explanation": "Great choice! Navigating independently or verifying via internal channels denies the attacker leverage." if action_correct else "Caution: Engaging with the phishing link or replying directly compromises account security."
    }

    # Save to database
    submission_data = {
        "selected_indicators": list(selected_indicators),
        "selected_action": selected_action_id,
        "indicator_score": indicator_score,
        "action_score": action_score
    }
    
    event_id = save_simulation_event(
        scenario_id=scenario.get("db_id", 1),
        selected_answers=submission_data,
        score=total_score,
        user_id=user_id
    )

    return {
        "event_id": event_id,
        "scenario_code": scenario_code,
        "scenario_title": scenario["title"],
        "total_score": total_score,
        "indicator_score": indicator_score,
        "action_score": action_score,
        "action_correct": action_correct,
        "teaching_point": scenario.get("teaching_point", ""),
        "indicator_feedback": indicator_feedback,
        "action_feedback": action_feedback
    }
