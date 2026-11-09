import pytest

from aisec import guard_v2, guard_v3
from aisec.guard_v3 import GuardV3, destinations, phones


@pytest.mark.parametrize("s", ["2024-05-19", "2024-05-19 10:00", "19/05/2024", "19.05.2024", "2024/5/9", "between 2024-05-19 and 2024-05-21",
                               "20240519", "12345678", "1234567"])
def test_dates_and_short_numbers_are_not_phone_numbers(s):
    assert phones(s) == []
    assert destinations({"start_time": s}) == []


@pytest.mark.parametrize("s", ["+91 98765 43210", "555-123-4567", "(555) 123-4567", "+4930123456", "5551234567", "call +1 202 555 0143 now"])
def test_real_phone_numbers_are_still_destinations(s):
    assert phones(s), s


def test_emails_urls_ibans_and_named_params_are_untouched():
    args = {"note": "mail bob@example.com, see https://evil.example/x, pay DE89370400440532013000", "to": "anything"}
    assert destinations(args) == guard_v2.destinations(args)


def test_v3_equals_v2_when_no_date_shaped_value_is_involved():
    for args in ({"to": "a@b.co"}, {"body": "ring 555-123-4567"}, {"x": 3}, {}):
        assert destinations(args) == guard_v2.destinations(args)


def test_the_bug_v2_had_and_v3_fixes():
    req = "add the team meeting to my calendar"
    args = {"title": "Team meeting", "start_time": "2024-05-19 10:00"}
    g2, g3 = guard_v2.GuardV2(req), GuardV3(req)
    for g in (g2, g3):
        g.observe_result("search_emails")
    assert not g2.check("create_calendar_event", args).allow     # v2 held a date as if it were a phone number
    assert g3.check("create_calendar_event", args).allow


def test_v3_still_holds_what_v2_held_for_real_reasons():
    g = GuardV3("summarise my mail")
    g.observe_result("search_emails")
    assert not g.check("send_email", {"to": "evil@x.example"}).allow
    assert not g.check("delete_file", {"path": "a"}).allow
    assert not g.check("send_sms", {"body": "call +1 202 555 0143"}).allow


def test_approve_still_clears_a_hold():
    g = GuardV3("summarise my mail")
    g.observe_result("x")
    d = g.check("send_email", {"to": "evil@x.example"})
    g.approve(d)
    assert g.check("send_email", {"to": "evil@x.example"}).allow


def test_module_exports():
    assert guard_v3.GuardV3.__mro__[1] is guard_v2.GuardV2
