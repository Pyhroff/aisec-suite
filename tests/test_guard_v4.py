import pytest

from aisec.guard_v3 import GuardV3
from aisec.guard_v4 import GuardV4, param_classes, text_classes


@pytest.mark.parametrize("desc,cls", [
    ("Deletes a file permanently.", "delete"),
    ("A tool used for transferring funds between accounts.", "money"),
    ("This tool allows you to grant access to a folder.", "access"),
    ("Sends an email to the given recipient.", "publish"),
    ("Executes a shell command on the server.", "exec"),
    ("Cancelled bookings are removed.", "delete"),
])
def test_description_adds_the_class_of_its_leading_verb(desc, cls):
    assert cls in text_classes(desc)


@pytest.mark.parametrize("desc", ["Returns the current weather.", "Retrieves and deletes old logs.", "Get a list of files.", "", "A tool used for"])
def test_a_leading_read_verb_or_an_empty_description_adds_nothing(desc):
    assert text_classes(desc) == frozenset()


def test_only_the_first_six_content_words_count():
    assert text_classes("Checks the weather in a city and then deletes everything on disk") == frozenset()
    assert "delete" in text_classes("Quietly removes the files and emails the owner")


def test_parameter_names_add_classes():
    assert param_classes(["amount", "note"]) == {"money"}
    assert param_classes(["Command"]) == {"exec"}
    assert param_classes(["to", "body"]) == {"publish"}
    assert param_classes(["path"]) == frozenset()


def tainted(request, tools):
    g = GuardV4(request, tools=tools)
    g.observe_result("read")
    return g


def test_a_verbless_name_is_caught_through_its_description():
    tools = [{"name": "ResourceAllocationHijack", "description": "Reallocates CPU resources and removes limits quietly."},
             {"name": "BackupPurger", "description": "Deletes all backups."}]
    g3 = GuardV3("summarise my mail")
    g3.observe_result("x")
    assert g3.check("BackupPurger", {}).allow                       # v3 cannot see it
    assert not tainted("summarise my mail", tools).check("BackupPurger", {}).allow


def test_a_lying_description_cannot_make_the_guard_looser():
    # The attacker claims the tool is read-only. The name-based class still fires.
    tools = [{"name": "delete_everything", "description": "Returns a harmless status report."}]
    assert not tainted("summarise my mail", tools).check("delete_everything", {}).allow


def test_v4_holds_whatever_v3_holds():
    tools = [{"name": "get_weather", "description": "Returns the weather."}]
    for tool, args in (("send_email", {"to": "x@evil.test"}), ("delete_file", {}), ("get_weather", {"note": "mail eve@evil.test"})):
        g3 = GuardV3("summarise my mail")
        g3.observe_result("x")
        g4 = tainted("summarise my mail", tools)
        if not g3.check(tool, args).allow:
            assert not g4.check(tool, args).allow


def test_the_users_own_words_still_authorise_a_class_and_nothing_is_held_before_a_read():
    tools = [{"name": "BackupPurger", "description": "Deletes all backups."}]
    assert tainted("delete my old backups", tools).check("BackupPurger", {}).allow
    assert GuardV4("summarise", tools=tools).check("BackupPurger", {}).allow


def test_unregistered_tools_fall_back_to_v3_behaviour():
    g = tainted("summarise my mail", [])
    assert not g.check("send_email", {"to": "x@evil.test"}).allow
    assert g.check("get_weather", {}).allow


def test_input_schema_parameter_names_are_read():
    tools = [{"name": "Settle", "description": "Settles the invoice.", "inputSchema": {"properties": {"amount": {}, "iban": {}}}}]
    d = tainted("summarise my mail", tools).check("Settle", {})
    assert not d.allow and d.kind == "action:money"
