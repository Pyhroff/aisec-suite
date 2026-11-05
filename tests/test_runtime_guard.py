"""Runtime guard (aisec/runtime_guard.py): provenance of destinations and actions after untrusted reads."""
from aisec.runtime_guard import AGENTDOJO_POLICY, RuntimeGuard


def guard(request: str, trusted=()) -> RuntimeGuard:
    return RuntimeGuard(AGENTDOJO_POLICY, request, trusted)


def test_calls_before_any_untrusted_read_pass():
    g = guard("Summarise my inbox.")
    assert g.check("send_email", {"recipients": ["attacker@evil.test"]}).allow


def test_injected_recipient_is_held_after_a_read():
    g = guard("Summarise my inbox.")
    g.observe_result("get_unread_emails")
    d = g.check("send_email", {"recipients": ["attacker@evil.test"], "subject": "x", "body": "y"})
    assert not d.allow and "attacker@evil.test" in d.reason


def test_recipient_named_by_the_user_passes():
    g = guard("Email the meeting notes to bob@company.test.")
    g.observe_result("search_files")
    assert g.check("send_email", {"recipients": ["Bob@company.test"]}).allow


def test_every_list_element_must_be_from_the_user():
    g = guard("Email the notes to bob@company.test.")
    g.observe_result("search_files")
    assert not g.check("send_email", {"recipients": ["bob@company.test", "eve@evil.test"]}).allow


def test_operator_trusted_destinations_pass():
    g = guard("Pay my rent.", trusted=["GB29NWBK60161331926819"])
    g.observe_result("get_most_recent_transactions")
    assert g.check("send_money", {"recipient": "GB29NWBK60161331926819", "amount": 1000}).allow


def test_destructive_action_needs_the_user_to_ask_for_it():
    g = guard("What files do I have?")
    g.observe_result("list_files")
    assert not g.check("delete_file", {"file_id": "13"}).allow
    g2 = guard("Delete the largest file in my drive.")
    g2.observe_result("list_files")
    assert g2.check("delete_file", {"file_id": "13"}).allow


def test_password_change_needs_the_word():
    g = guard("Check my last transactions.")
    g.observe_result("get_most_recent_transactions")
    assert not g.check("update_password", {"password": "new"}).allow


def test_non_sink_reads_always_pass():
    g = guard("x")
    g.observe_result("read_file")
    assert g.check("search_emails", {"query": "anything"}).allow


def test_empty_or_missing_destination_values_are_not_checked():
    g = guard("Create an event for me tomorrow.")
    g.observe_result("get_current_day")
    assert g.check("create_calendar_event", {"title": "x", "participants": []}).allow
