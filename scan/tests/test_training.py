"""--training: practise reading a report on a made-up phone.

Pinned here:
  - each scenario gives the result it is meant to teach (findings / worth a look /
    nothing found) through the ordinary phone check and report;
  - every output says it is a training example: the readable report, the JSON
    report and the relay rules for assistants;
  - the example is made in the temp folder and removed when the tool exits;
  - it reads no real evidence and no real indicators: options that would point it
    at either, or produce something meant to be sent, are refused;
  - every indicator is invented and cannot name anything real;
  - the post-scan menu will not make a sharing summary or evidence bundle;
  - the start menu offers it and sets only the scenario;
  - a normal report carries no training marker.
"""

from __future__ import annotations

import contextlib
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, contract, menu, training, workflow  # noqa: E402
from zbtriage.iocs import load_any  # noqa: E402


def run(*argv, tmp):
    """Run the CLI in a private temp folder; return (exit code, stdout, JSON report)."""
    report = os.path.join(tmp, "report.json")
    out, err = io.StringIO(), io.StringIO()
    with patch.dict(os.environ, {"TMPDIR": tmp, "TEMP": tmp, "TMP": tmp}), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv) + ["--no-menu", "--no-banner", "--json", report])
    doc = json.load(open(report, encoding="utf-8")) if os.path.exists(report) else None
    return code, out.getvalue(), doc, err.getvalue()


class TrainingCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="trn_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestScenarios(TrainingCase):
    def test_spyware_has_findings_with_grades(self):
        code, text, doc, _ = run("--training", tmp=self.tmp)
        self.assertEqual(code, 2)
        self.assertEqual(doc["training"]["scenario"], "spyware")
        grades = {h["evidence"] for m in doc["modules"].values() for h in m["hits"]}
        self.assertEqual(grades, {"on-device", "device-log"})
        families = {h["family"] for m in doc["modules"].values() for h in m["hits"]}
        self.assertEqual(families, {training.TRAINING_FAMILY})

    def test_worth_a_look_has_leads_but_no_findings(self):
        code, text, doc, _ = run("--training", "worth-a-look", tmp=self.tmp)
        self.assertEqual(doc["verdict"]["hits_total"], 0)
        self.assertNotEqual(code, 2)
        whats = " | ".join(l["what"] for l in doc["worth_a_look"])
        for expected in ("outside an app store", "accessibility access",
                         "verification", "security updates are"):
            self.assertIn(expected, whats)

    def test_clean_has_nothing_but_still_lists_gaps(self):
        code, text, doc, _ = run("--training", "clean", tmp=self.tmp)
        self.assertEqual(doc["verdict"]["hits_total"], 0)
        self.assertEqual(doc["worth_a_look"], [])
        self.assertTrue(doc["verdict"]["gaps"])
        self.assertIn("NOT a clean bill of health", text)

    def test_only_the_phone_check_runs(self):
        _, _, doc, _ = run("--training", tmp=self.tmp)
        self.assertEqual(set(doc["modules"]), {"android", "android-intrusion"})
        self.assertFalse(doc["ioc_set"]["feeds"]["used"])


class TestLabelling(TrainingCase):
    def test_readable_report_starts_and_ends_as_training(self):
        _, text, _, _ = run("--training", tmp=self.tmp)
        lines = [l for l in text.splitlines() if l.strip() and not l.startswith("[")]
        self.assertIn("TRAINING EXAMPLE - NOT A REAL CHECK", "\n".join(lines[:3]))
        self.assertIn("TRAINING NOTES", "\n".join(lines[-20:]))

    def test_assistants_are_told_first(self):
        _, _, doc, _ = run("--training", "clean", tmp=self.tmp)
        self.assertEqual(doc["must_relay"][0]["id"], "training")
        self.assertIn("made-up phone", doc["must_relay"][0]["text"])

    def test_saved_readable_report_is_labelled(self):
        saved = os.path.join(self.tmp, "readable.txt")
        run("--training", "--report", saved, tmp=self.tmp)
        self.assertIn("TRAINING EXAMPLE", open(saved, encoding="utf-8").read())

    def test_normal_reports_are_not_marked(self):
        doc = {"verdict": {}, "scope": {}}
        self.assertNotIn("training", [m["id"] for m in contract.contract_must_relay(doc)])
        self.assertEqual(training.training_banner(doc), ([], []))
        # A marker must be the real one, not any truthy value.
        doc["training"] = {"scenario": "spyware", "synthetic": "yes"}
        self.assertNotIn("training", [m["id"] for m in contract.contract_must_relay(doc)])


class TestCleanup(TrainingCase):
    def test_example_is_deleted_after_the_run(self):
        run("--training", tmp=self.tmp)
        self.assertEqual(glob.glob(os.path.join(self.tmp, "zbt_training_*")), [])

    def test_example_is_deleted_when_the_scan_fails(self):
        with patch.object(cli, "_run_modules", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                run("--training", tmp=self.tmp)
        self.assertEqual(glob.glob(os.path.join(self.tmp, "zbt_training_*")), [])


class TestRefusals(TrainingCase):
    REFUSED = (["--phone", "x"], ["--target", "x", "--scan-type", "targeted"],
               ["--scan-type", "full"], ["--iocs", "x.txt"], ["--share-json", "s.json"],
               ["--evidence-bundle", "e.zip"], ["--update"], ["--patterns"],
               ["--collect-android", "x"], ["--latest"], ["--preview"],
               ["--indicator-cache", "x"], ["--extended-windows"])

    def test_real_evidence_and_sending_options_are_refused(self):
        for extra in self.REFUSED:
            with self.subTest(extra=extra):
                with contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit) as stop:
                    cli._parse(["--training"] + extra)
                self.assertNotEqual(stop.exception.code, 0)
                self.assertIn("--training", err.getvalue())

    def test_unknown_scenario_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli._parse(["--training", "pegasus"])


class TestIndicatorsAreInvented(TrainingCase):
    def test_nothing_real_can_match(self):
        path = os.path.join(self.tmp, "i.stix2.json")
        training._trn_indicators(path)
        values = {i.type: i.value for i in load_any(path).indicators}
        self.assertTrue(values["domain"].endswith(".invalid"))      # RFC 2606
        self.assertTrue(values["app-id"].startswith("org.example."))
        self.assertEqual(len(values), 6)

    def test_real_curated_indicators_are_not_in_the_example(self):
        shipped = []
        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        for name in ("adfection_iocs.txt", "curated_mercenary.txt"):
            shipped.append(open(os.path.join(repo, "iocs", name), encoding="utf-8").read())
        path = os.path.join(self.tmp, "i.stix2.json")
        training._trn_indicators(path)
        for ind in load_any(path).indicators:
            for text in shipped:
                self.assertNotIn(ind.value, text)


class TestMenus(TrainingCase):
    def test_start_menu_offers_practice(self):
        labels = [i.label for i in menu._MN_ITEMS]
        self.assertIn("Practise with a training example", labels)
        number = str(labels.index("Practise with a training example") + 1)
        args = cli._parse([])
        stdin = io.StringIO(number + "\n2\n")
        ok = menu.choose_scan(args, lambda: None, stdin=stdin, stderr=io.StringIO(),
                              stdout_visible=True)
        self.assertTrue(ok)
        self.assertEqual(args.training, "worth-a-look")
        self.assertIsNone(args.phone)

    def test_training_flag_skips_the_start_menu(self):
        args = SimpleNamespace(no_menu=False)
        self.assertFalse(menu.menu_wanted(["--training"], args))

    def test_post_scan_menu_will_not_export(self):
        doc = {"training": training.training_marker(SimpleNamespace(training="spyware")),
               "verdict": {"gaps": []}, "scope": {}, "modules": {}}
        err = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO("4\n5\n0\n")), \
                patch.object(sys, "stderr", err), \
                patch("zbtriage.report.share_summary", side_effect=AssertionError("exported")), \
                patch("zbtriage.handoff.handoff_write", side_effect=AssertionError("exported")):
            workflow.workflow_menu(doc, SimpleNamespace())
        self.assertIn("Not available for a training example", err.getvalue())


class TestSingleFileBuild(TrainingCase):
    def test_single_file_build_runs_training(self):
        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        built = os.path.join(self.tmp, "single.py")
        subprocess.run([sys.executable, os.path.join(repo, "build", "bundle.py"), repo, built],
                       check=True, capture_output=True)
        env = dict(os.environ, TMPDIR=self.tmp, TEMP=self.tmp, TMP=self.tmp)
        done = subprocess.run([sys.executable, "-I", built, "--training", "--no-menu",
                               "--no-banner", "--no-pause"], capture_output=True, text=True,
                              env=env, stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("TRAINING EXAMPLE - NOT A REAL CHECK", done.stdout)
        self.assertEqual(glob.glob(os.path.join(self.tmp, "zbt_training_*")), [])


if __name__ == "__main__":
    unittest.main()
