"""Interactive choices and outputs, with every scan/download replaced or scoped."""
import contextlib
import datetime
import io
import json
from pathlib import Path
import sys
import types
from unittest.mock import patch
import zipfile

import pytest

from zbtriage import cli, menu, report, workflow
from zbtriage.result import ModuleResult, Hit, EV_CONTACTED
from test_expanded_capabilities import context, BAD, SAMPLE, DIGEST
from test_followup_fixes import bundle


class Terminal(io.StringIO):
    def isatty(self):
        return True


def wf_document():
    result = ModuleResult("browser")
    result.ran("history")
    result.add_hit(Hit(BAD, "fixture History", "recorded visit", evidence=EV_CONTACTED))
    return report.build_document(context().iocs, [result], datetime.datetime.now())


@pytest.mark.parametrize("choice", ["0\n", "", "q\n"])
def test_quit_has_distinct_exit_and_no_reports(tmp_path, bundle, choice):
    for name, api in (("source", cli), ("bundle", bundle)):
        out, err = Terminal(), Terminal()
        path = tmp_path / (name + ".json")
        with patch.object(sys, "stdin", Terminal(choice)), patch.object(sys, "stderr", err), \
             patch.object(sys, "stdout", out), patch.object(api, "_force_utf8_io", lambda: None):
            code = api.main(["--no-banner", "--json", str(path)])
        assert code == 4
        assert "Nothing was checked" in err.getvalue()
        assert not path.exists()
        assert not out.getvalue()


def test_menu_default_invalid_input_and_back_do_not_change_scope(tmp_path, bundle):
    for api in (menu, bundle):
        args = cli._parse([])
        assert api.choose_scan(args, lambda: pytest.fail("update"), stdin=Terminal("bad\n\n"), stderr=Terminal())
        assert args.scan_type == "default" and args._interactive_workflow
        args = cli._parse([])
        assert not api.choose_scan(args, lambda: pytest.fail("update"),
                                   stdin=Terminal("3\n" + str(tmp_path) + "\n0\n0\n"), stderr=Terminal())
        assert args.scan_type == "default" and not args.target


def _menu_number(api, args, label):
    """The menu number of an entry, found by name so new entries never shift the tests."""
    session = api._MnSession(args, None, None, None, False)
    shown = [i.label for i in api._MN_ITEMS if i.available(session)]
    return shown.index(label) + 1


def test_menu_update_requires_confirmation_and_only_calls_mock(bundle):
    for api in (menu, bundle):
        calls = []
        args = cli._parse([])
        n = _menu_number(api, args, "Update the indicator lists")
        api.choose_scan(args, lambda: calls.append("update"), stdin=Terminal("%d\nn\n0\n" % n), stderr=Terminal())
        assert not calls
        api.choose_scan(args, lambda: calls.append("update"), stdin=Terminal("%d\ny\n\n0\n" % n), stderr=Terminal())
        assert calls == ["update"]


def test_explicit_scans_and_noninteractive_input_never_open_menus(bundle):
    for api in (menu, bundle):
        args = cli._parse([])
        assert not api.menu_wanted([], args, stdin=io.StringIO(), stderr=Terminal())
        for token in ("--no-menu", "--scan-type=full", "--phone", "--collect-android", "--preview"):
            assert not api.menu_wanted([token], args, stdin=Terminal(), stderr=Terminal())


def test_all_outputs_and_handoff_run_in_both_entrypoints(tmp_path, bundle):
    selected = tmp_path / "original.bin"
    selected.write_bytes(SAMPLE)
    feed = tmp_path / "feed.txt"
    feed.write_text(DIGEST + "\tsample\tprimary\tfixture\n")
    for name, api in (("source", cli), ("bundle", bundle)):
        full, minimal, text, archive = [tmp_path / (name + ext) for ext in (".json", ".share.json", ".txt", ".zip")]
        args = ["--no-menu", "--no-banner", "--iocs", str(feed), "--scan-type", "targeted", "--target", str(selected),
                "--json", str(full), "--share-json", str(minimal), "--report", str(text),
                "--evidence-bundle", str(archive), "--evidence-file", str(selected)]
        with patch.object(api, "_force_utf8_io", lambda: None), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = api.main(args)
        assert code == 2
        document = json.loads(full.read_text())
        assert document["indicator_fingerprints"]["combined"]
        assert document["completed_at"] and document["scope"]["scanned"]
        assert document["verdict"]["findings_total"] == 1
        assert SAMPLE == selected.read_bytes()
        assert text.read_text(encoding="utf-8")
        assert str(selected) not in minimal.read_text()
        with zipfile.ZipFile(archive) as zf:
            assert any(zf.read(member) == SAMPLE for member in zf.namelist())


def test_readable_output_failure_preserves_json_and_console(tmp_path, bundle):
    for api in (report, bundle):
        result = ModuleResult("browser")
        result.ran("history")
        result.add_hit(Hit(BAD, "fixture", "fixture", evidence=EV_CONTACTED))
        args = cli._parse(["--no-menu", "--json", str(tmp_path / "full.json"), "--report", str(tmp_path / "missing" / "text.txt")])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = api.finalize_report(context().iocs, [result], datetime.datetime.now(), args)
        assert code == 1
        assert json.loads(Path(args.json).read_text())["exit_code"] == 2
        assert out.getvalue()


@pytest.mark.parametrize("extra", [
    ["--report", "same", "--json", "same"],
    ["--evidence-file", "file"],
    ["--report", "text", "--update"],
    ["--post-menu", "--no-menu"],
])
def test_invalid_workflow_combinations_are_refused(extra, bundle):
    for api in (cli, bundle):
        with pytest.raises(SystemExit) as error, contextlib.redirect_stderr(io.StringIO()):
            api.main(extra)
        assert error.value.code == 1


def test_post_menu_inspection_and_summary_export(tmp_path, bundle):
    doc = wf_document()
    doc["modules"]["browser"]["hits"][0]["detail"] = "untrusted\x1b[2J" + BAD
    for name, api in (("source", workflow), ("bundle", bundle)):
        summary = tmp_path / (name + ".summary.json")
        err = Terminal()
        with patch.object(sys, "stdin", Terminal("1\n1\n2\n4\n" + str(summary) + "\n0\n")), patch.object(sys, "stderr", err):
            assert api.workflow_menu(doc, cli._parse([]))
        assert "not instructions" in err.getvalue()
        assert "\x1b" not in err.getvalue()
        assert BAD not in summary.read_text()
        assert json.loads(summary.read_text())["verdict"]["findings_total"] == 1


def test_indicator_fingerprint_is_order_independent_and_sensitive():
    a = context().iocs
    b = context().iocs
    b.indicators.reverse()
    assert workflow.workflow_fingerprints(a) == workflow.workflow_fingerprints(b)
    b.indicators.pop()
    assert workflow.workflow_fingerprints(a)["combined"] != workflow.workflow_fingerprints(b)["combined"]


def test_launcher_preserves_visible_prompts_and_checks_report_existence():
    text = (Path(__file__).resolve().parents[1] / "run-scan.cmd").read_text()
    invocation = next(line for line in text.splitlines() if line.startswith("%PY% -X"))
    assert '--report "%TXT%"' in invocation and ">" not in invocation
    assert 'if "%RC%"=="4"' in text
    assert 'if exist "%JSON%"' in text


@pytest.mark.parametrize("mode", ["phone", "target", "pattern"])
def test_reports_cannot_replace_files_inside_input_roots(tmp_path, bundle, mode):
    original = tmp_path / "History"
    original.write_bytes(b"synthetic source evidence")
    flags = (["--phone", str(tmp_path)] if mode == "phone" else
             ["--scan-type", "targeted", "--target", str(tmp_path)] if mode == "target" else
             ["--patterns", "--pattern-path", str(tmp_path)])
    for api in (cli, bundle):
        with contextlib.redirect_stderr(io.StringIO()):
            assert api.main(flags + ["--report", str(original)]) == 1
        assert original.read_bytes() == b"synthetic source evidence"


def test_post_menu_refuses_overwrite_of_original_even_with_yes(tmp_path, bundle):
    original = tmp_path / "evidence.bin"
    original.write_bytes(b"preserve")
    args = cli._parse(["--scan-type", "targeted", "--target", str(original)])
    for api in (workflow, bundle):
        with patch.object(sys, "stdin", Terminal("3\n" + str(original) + "\ny\n0\n")), patch.object(sys, "stderr", Terminal()):
            assert not api.workflow_menu(wf_document(), args)
        assert original.read_bytes() == b"preserve"


def test_phone_menu_guards_markers_before_stat(tmp_path, bundle):
    from zbtriage import localpaths
    for api, guard_owner in ((menu, localpaths), (bundle, bundle)):
        with patch.object(guard_owner, "path_problem", return_value="refused link"), \
             patch.object(api.os.path, "isfile", side_effect=AssertionError("followed refused marker")):
            assert not api._mn_local_marker(str(tmp_path), "Manifest.plist")


def test_redirected_report_is_visible_before_followup(tmp_path, bundle):
    selected = tmp_path / "original.bin"
    selected.write_bytes(SAMPLE)
    feed = tmp_path / "feed.txt"
    feed.write_text(DIGEST + "\tsample\tprimary\tfixture\n")
    for api in (cli, bundle):
        out, err = io.StringIO(), Terminal()
        with patch.object(sys, "stdin", Terminal("0\n")), patch.object(sys, "stdout", out), \
             patch.object(sys, "stderr", err), patch.object(api, "_force_utf8_io", lambda: None):
            code = api.main(["--no-banner", "--post-menu", "--iocs", str(feed), "--scan-type", "targeted", "--target", str(selected)])
        assert code == 2
        assert out.getvalue().strip() in err.getvalue()
        assert err.getvalue().index(out.getvalue().strip()) < err.getvalue().index("What would you like to do next?")


def test_post_menu_export_requires_confirmed_preview(tmp_path, bundle):
    for n, api in enumerate((workflow, bundle)):
        archive = tmp_path / (str(n) + ".zip")
        args = cli._parse([])
        err = Terminal()
        with patch.object(sys, "stdin", Terminal("5\n\n" + str(archive) + "\nn\n0\n")), patch.object(sys, "stderr", err):
            assert api.workflow_menu(wf_document(), args)
        assert not archive.exists()
        with patch.object(sys, "stdin", Terminal("5\n\n" + str(archive) + "\ny\n0\n")), patch.object(sys, "stderr", err):
            assert api.workflow_menu(wf_document(), args)
        assert archive.exists()
        assert err.getvalue().index("Total payload") < err.getvalue().index("Create this private bundle")
