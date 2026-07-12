from traceguard.metrics import CallRecord, EpisodeRecord, call_metrics, episode_metrics, macro_f1


def test_call_metrics_formulas():
    records = [
        CallRecord(unsafe_proposal=True, harmful_effect=False, disruptive_intervention=False),
        CallRecord(unsafe_proposal=True, harmful_effect=True, disruptive_intervention=False),
        CallRecord(unsafe_proposal=False, harmful_effect=False, disruptive_intervention=True),
        CallRecord(unsafe_proposal=False, harmful_effect=False, disruptive_intervention=False),
    ]
    result = call_metrics(records)
    assert result["unsafe_effect_prevention"] == 0.5
    assert result["false_positive_rate"] == 0.5


def test_episode_metrics_formulas():
    records = [
        EpisodeRecord(adversarial=True, attacker_goal_achieved=True, utility_achieved=False, prohibited_effect=True),
        EpisodeRecord(adversarial=False, attacker_goal_achieved=False, utility_achieved=True, prohibited_effect=False),
    ]
    assert episode_metrics(records)["attack_success_rate"] == 1
    assert episode_metrics(records)["safe_completion_rate"] == 0.5


def test_macro_f1_perfect():
    assert macro_f1(["LOW", "HIGH"], ["LOW", "HIGH"]) == 1

