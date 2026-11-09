from aisec.guard_v2 import GuardV2, classify, destinations, is_read_only, name_tokens


def test_name_tokens_handle_every_naming_style():
    assert name_tokens("GmailDeleteEmails") == ["gmail", "delete", "emails"]
    assert name_tokens("gmail_delete_emails") == ["gmail", "delete", "emails"]
    assert name_tokens("gmail-delete.emails") == ["gmail", "delete", "emails"]
    assert name_tokens("HTTPServerSendSMS") == ["http", "server", "send", "sms"]


def test_classes_and_read_only():
    assert classify("AugustSmartLockUnlockDoor") >= {"access"}
    assert "delete" in classify("delete_file")
    assert "money" in classify("BankManagerTransferFunds")
    assert is_read_only("search_emails") and not is_read_only("send_email")
    assert classify("get_weather") == frozenset()


def test_destinations_by_shape_and_by_name():
    assert destinations({"note": "mail bob@example.com now", "n": 3}) == ["bob@example.com"]
    assert destinations({"to": "anything"}) == ["anything"]
    assert "https://evil.example/x" in destinations({"body": "see https://evil.example/x"})


def test_nothing_held_before_untrusted_content():
    g = GuardV2("read my notes")
    assert g.check("delete_file", {"path": "a"}).allow


def test_destination_must_come_from_the_user():
    g = GuardV2("email the report to ann@corp.example")
    g.observe_result("read_file")
    assert g.check("send_email", {"to": "ann@corp.example"}).allow
    d = g.check("send_email", {"to": "evil@x.example"})
    assert not d.allow and d.kind == "destination"


def test_destination_free_action_needs_the_user_to_ask():
    g = GuardV2("summarise my unread mail")
    g.observe_result("search_emails")
    d = g.check("AugustSmartLockUnlockDoor", {})
    assert not d.allow and d.kind == "action:access"
    assert GuardV2("please unlock the front door").check("unlock_door", {}).allow  # untainted
    g2 = GuardV2("please unlock the front door")
    g2.observe_result("x")
    assert g2.check("unlock_door", {}).allow


def test_prefix_matching_of_request_words():
    g = GuardV2("I am deleting old drafts")
    g.observe_result("x")
    assert g.check("DeleteEmails", {}).allow


def test_read_only_tools_pass_unless_destination_is_foreign():
    g = GuardV2("what is on my calendar")
    g.observe_result("x")
    assert g.check("search_events", {"query": "meeting"}).allow
    assert not g.check("get_webpage", {"url": "https://evil.example/?d=1"}).allow


def test_approve_stops_repeat_prompts():
    g = GuardV2("tidy up")
    g.observe_result("x")
    d = g.check("send_email", {"to": "bob@x.example"})
    assert not d.allow
    g.approve(d)
    assert g.check("send_email", {"to": "bob@x.example"}).allow
    assert not g.check("send_email", {"to": "eve@x.example"}).allow
    d = g.check("delete_file", {})
    g.approve(d)
    assert g.check("remove_item", {}).allow


def test_unrecognised_verb_is_not_held():
    g = GuardV2("hello")
    g.observe_result("x")
    assert g.check("frobnicate_widgets", {}).allow
