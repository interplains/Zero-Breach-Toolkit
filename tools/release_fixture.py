"""Child-process CLI fixtures for release_check.py; not a scanner feature.

Only discovery roots and OS collectors are substituted. The actual CLI,
browser/hash/host/pattern modules, evidence grading, JSON and text rendering run.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import sys
import tarfile
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "release-fixture.invalid"
PAYLOAD = b"Harmless Zero Breach release test bytes; not malware.\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def main():
    target, case, directory, scanner = sys.argv[1:]
    root = Path(directory).resolve()
    inputs, outputs, scratch = root / "inputs", root / "outputs", root / "tmp"
    for p in (inputs, outputs, scratch):
        p.mkdir(parents=True)
    # Even an accidentally unpatched discovery point sees a synthetic home.
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "SystemRoot"):
        os.environ[key] = str(inputs)
    for key in ("TMP", "TEMP", "TMPDIR"):
        os.environ[key] = str(scratch)
    import tempfile
    tempfile.tempdir = str(scratch)
    sys.path[:0] = [str(ROOT / "scan"), str(ROOT / "scan/tests")]
    if target == "bundle":
        spec = importlib.util.spec_from_file_location("release_candidate", scanner)
        cli = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cli
        spec.loader.exec_module(cli)
        browser = hashes = host = patterns = reporting = traces = cli
    else:
        from zbtriage import cli, report as reporting
        from zbtriage.modules import browser, hashscan as hashes, host, patternscan as patterns
        from zbtriage.modules import traces

    profile = inputs / "Browser" / "Default"
    profile.mkdir(parents=True)
    history = profile / "History"
    with sqlite3.connect(str(history)) as con:
        con.execute("CREATE TABLE urls (url TEXT, title TEXT)")
        con.execute("INSERT INTO urls VALUES (?, ?)", ("https://example.invalid/", "ordinary"))
    if case in ("corrupt", "hit-and-gap"):
        history.write_bytes(b"not a SQLite database")
    if case == "history-host-reference":
        with sqlite3.connect(str(history)) as con:
            con.execute("UPDATE urls SET url=?, title=?", ("https://" + DOMAIN + "/?q=sub." + DOMAIN, "reference to sub." + DOMAIN))
    if case in ("contact", "hit-and-gap"):
        cookie = profile / "Network" / "Cookies"
        cookie.parent.mkdir()
        with sqlite3.connect(str(cookie)) as con:
            con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                        "creation_utc INTEGER, encrypted_value BLOB)")
            con.execute("INSERT INTO cookies VALUES (?, 'sid', 13300000000000000, ?)",
                        ("." + DOMAIN, b"PRIVATE_COOKIE_SENTINEL_DO_NOT_REPORT"))
    if case == "reference":
        blob = profile / "Local Storage" / "leveldb" / "000001.log"
        blob.parent.mkdir(parents=True)
        blob.write_text("saved article https://" + DOMAIN + "/research", encoding="utf-8")
    files = inputs / "Files"
    files.mkdir()
    (files / "ordinary.dll").write_bytes(PAYLOAD if case in ("hash", "quick", "workflow-handoff") else b"ordinary")
    feed = inputs / "iocs.txt"
    feed.write_text("# as-of: 2026-10-19\n" + DOMAIN + "\tdelivery\tprimary\tfixture\n"
                    + DIGEST + "\tsample\tprimary\tfixture\n", encoding="utf-8")
    if case == "history-host-reference":
        with feed.open("a", encoding="utf-8") as fh:
            fh.write("sub." + DOMAIN + "\tdelivery\tprimary\tfixture\n")
    if case == "phone-process":
        feed = inputs / "phone-iocs.stix2"
        feed.write_text(json.dumps({"objects": [{"type": "indicator", "id": "indicator--fixture",
            "pattern": "[app:id='com.release.fixture.spy']", "modified": "2026-10-19T00:00:00Z"}]}), encoding="utf-8")
        phone = inputs / "phone"
        phone.mkdir()
        (phone / "packages.json").write_text("[]", encoding="utf-8")
        (phone / "processes.txt").write_text("USER PID NAME\nu0_a1 123 com.release.fixture.spy\n", encoding="utf-8")
    if case == "windows-records":
        from test_windows_execution import _we_prefetch, _we_amcache
        (files / "fixture.pf").write_bytes(_we_prefetch(paths=[]))
        (files / "Amcache.hve").write_bytes(_we_amcache())
        feed = inputs / "execution.stix2"
        feed.write_text(json.dumps({"objects": [{"type": "indicator", "id": "indicator--fixture",
            "pattern": "[file:name='fixture-spy.exe']", "modified": "2026-10-19T00:00:00Z"}]}), encoding="utf-8")
    if case == "android-intrusion":
        phone = inputs / "phone"
        phone.mkdir()
        (phone / "packages.json").write_text("[]", encoding="utf-8")
        (phone / "intrusion_logs").mkdir()
        records = [{"dns_event": {"event_time": 1746979200000, "hostname": DOMAIN,
                    "ip_addresses": [], "package_name": "com.safe.app"}},
                   {"connect_event": {"event_time": 1746979201000, "ip_address": "203.0.113.8",
                    "port": 443, "package_name": "com.safe.app"}}]
        (phone / "intrusion_logs" / "events.txt").write_text("\n".join(json.dumps(row) for row in records), encoding="utf-8")
        with feed.open("a", encoding="utf-8") as fh:
            fh.write("203.0.113.8\tinfrastructure\tprimary\tfixture\n")
    if case in ("linux-startup", "macos-startup"):
        startup = inputs / "startup"
        startup.mkdir()
        if case == "linux-startup":
            (startup / "fixture.desktop").write_text("[Desktop Entry]\nType=Application\nExec=/opt/fixture-spy\n", encoding="utf-8")
        else:
            (startup / "fixture.plist").write_bytes(plistlib.dumps({"Label": "fixture", "Program": "/opt/fixture-spy"}))
        feed = inputs / "startup.stix2"
        feed.write_text(json.dumps({"objects": [{"type": "indicator", "id": "indicator--fixture",
            "pattern": "[file:path='/opt/fixture-spy']", "modified": "2026-10-19T00:00:00Z"}]}), encoding="utf-8")
    if case == "unicode-report":
        phone = inputs / "phone"
        phone.mkdir()
        (phone / "packages.json").write_text("[]", encoding="utf-8")
        # The JSON inventory can carry a malformed filename on every host OS.
        # This exercises real readers and report writers without OS-dependent
        # permission to create such a filename on the test runner itself.
        (phone / "files.json").write_text(json.dumps([
            {"path": "/data/local/tmp/odd\ud800.dll", "sha256": DIGEST}]), encoding="utf-8")
    if case == "ios-row-recovery":
        phone = inputs / "phone"
        phone.mkdir()
        (phone / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
        (phone / "Info.plist").write_bytes(plistlib.dumps({"Installed Applications": []}))
        fid = hashlib.sha1(b"HomeDomain-Library/SMS/sms.db").hexdigest()
        with contextlib.closing(sqlite3.connect(phone / "Manifest.db")) as con:
            con.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
            con.execute("INSERT INTO Files VALUES(?,'HomeDomain','Library/SMS/sms.db',1,?)", (fid, b""))
            con.commit()
        (phone / fid[:2]).mkdir()
        with contextlib.closing(sqlite3.connect(phone / fid[:2] / fid)) as con:
            con.execute("CREATE TABLE message(text TEXT,date INTEGER,is_from_me INTEGER)")
            con.executemany("INSERT INTO message VALUES(?,0,0)", [
                ("x" * (2 * 1024 * 1024 + 100),), ("https://" + DOMAIN,)])
            con.commit()
    if case == "ios-wal":
        from test_ios_upgrade import db_bytes, backup
        raw, wal = db_bytes(inputs, "CREATE TABLE message(text,date,is_from_me)",
                            [("INSERT INTO message VALUES(?,0,0)", (DOMAIN,))], wal=True)
        phone = inputs / "phone"
        backup(phone, [("HomeDomain", "Library/SMS/sms.db", raw),
                       ("HomeDomain", "Library/SMS/sms.db-wal", wal)])
    if case == "ios-sysdiagnose":
        phone = inputs / "diagnostics.tar.gz"
        payload = json.dumps({"procName": "FixtureProcess", "captureTime": "2026-01-01T00:00:00Z"}).encode()
        with tarfile.open(phone, "w:gz") as archive:
            member = tarfile.TarInfo("sys/crash.ips")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        feed = inputs / "ios.stix2"
        feed.write_text(json.dumps({"objects": [{"type": "indicator", "pattern": "[process:name='FixtureProcess']"}]}), encoding="utf-8")
    hosts = inputs / "System32" / "drivers" / "etc" / "hosts"
    hosts.parent.mkdir(parents=True)
    # Protective blocklist entries must never create findings.
    hosts.write_text("127.0.0.1 localhost\n0.0.0.0 " + DOMAIN + "\n", encoding="utf-8")
    registered = inputs / "Registered" / "server.dll"
    if case == "patterns-localserver":
        registered = inputs / "Registered" / "folder.exe" / "payload.bat"
    registered.parent.mkdir(parents=True)
    engine = importlib.util.find_spec("yara_x") is not None
    if case in ("patterns", "patterns-localserver") and engine:
        from test_patterns import synthetic_mstic_fixture
        registered.write_bytes(synthetic_mstic_fixture())
    else:
        registered.write_bytes(b"ordinary registered file")
    before = snapshot(inputs)
    denied_activity = []
    original_network_guard = cli.no_network

    @contextlib.contextmanager
    def checked_network_guard():
        # The scanner's socket wrappers reject calls before Python emits an
        # audit event. Observe their recorder too, including caught attempts.
        with original_network_guard() as recorder:
            try:
                yield recorder
            finally:
                denied_activity.extend(recorder.attempts)

    # Runtime roots are the interpreter's own search path. The user site directory
    # belongs there too: when an optional engine is imported inside the audited
    # region, the import system lists and reads user site before finding the module
    # in the main one. That is Python looking for a module, not the scanner reading
    # evidence. Without it the gate fails on any machine that has a user site
    # directory unless PYTHONNOUSERSITE=1 is set, which hid a passing run behind an
    # environment variable. Sockets, subprocesses and every path outside the repo,
    # the fixture and the runtime are still denied.
    runtime_roots = [Path(sys.prefix), Path(sys.base_prefix)]
    try:
        import site
        if getattr(site, "ENABLE_USER_SITE", False):
            user_site = site.getusersitepackages()
            if isinstance(user_site, str):
                runtime_roots.append(Path(user_site))
            else:
                runtime_roots.extend(Path(p) for p in user_site)
    except Exception:
        pass
    allowed = tuple([root, ROOT]
                    + [p.absolute() for p in runtime_roots]
                    + [p.resolve() for p in runtime_roots])

    # Where the interpreter keeps compiled bytecode when it is NOT beside the source:
    # PYTHONPYCACHEPREFIX, and on a Mac Apple's own Python (~/Library/Caches/com.apple.python).
    # Only compiled-module files (.pyc) under those folders are let through, so a codec
    # or module import is not mistaken for the scanner reading evidence, while every
    # other file there stays denied.
    bytecode_roots = []
    if getattr(sys, "pycache_prefix", None):
        bytecode_roots.append(sys.pycache_prefix)
    if sys.platform == "darwin":
        bytecode_roots.append(os.path.join(os.path.expanduser("~"), "Library", "Caches", "com.apple.python"))
    bytecode_roots = [os.path.normcase(os.path.abspath(p)) for p in bytecode_roots]

    def within(path):
        # Lexical only; no link resolution before the scanner's locality guard.
        path = os.path.normcase(os.path.abspath(os.fspath(path)))
        if path.endswith(".pyc") and any(path.startswith(b + os.sep) for b in bytecode_roots):
            return True
        return any(path == os.path.normcase(str(base))
                   or path.startswith(os.path.normcase(str(base)) + os.sep) for base in allowed)

    def audit(event, args):
        if event.startswith("socket.") or event in ("subprocess.Popen", "os.system"):
            denied_activity.append(event)
            raise RuntimeError("fixture attempted external activity: " + event)
        if event in ("open", "os.listdir", "os.scandir") and args:
            path = args[0]
            if isinstance(path, (str, bytes, os.PathLike)) and not within(os.fsdecode(path)):
                denied_activity.append(event)
                raise RuntimeError("fixture attempted file access outside test/code/runtime roots")

    events = [{"Time": "2025-06-01T00:00:00", "Message": "ordinary.invalid"}]
    if case == "dns-off-retained-hit":
        events[0]["Message"] = DOMAIN
    if case.startswith("dns-cap-"):
        events = events * 50000
        if case == "dns-cap-hit":
            events[20000] = {"Time": "2025-06-01T00:00:00", "Message": DOMAIN}
        else:
            events = [{"Time": "2026-01-01T00:00:00", "Message": "ordinary.invalid"}] * 50000

    def ps_json(command, timeout=60):
        if "-ListLog " in command:
            return [{"IsEnabled": not case.startswith("dns-off-"),
                     "RecordCount": 0 if case == "dns-off-empty" else len(events) + int(case.startswith("dns-cap-"))}], ""
        if "Get-WinEvent -LogName " in command:
            require("-MaxEvents 50000" in command, "unexpected DNS read cap")
            if case == "dns-off-unreadable":
                return [], "fixture read denied"
            return events, ""
        if "Get-DnsClientCache" in command:
            return [{"Entry": DOMAIN, "Data": "0.0.0.0", "Type": 1}], ""
        if "Win32_OperatingSystem" in command:
            return [{"Boot": "2026-01-01T00:00:00"}], ""
        raise RuntimeError("unexpected OS query in fixture")

    entries = ([{"clsid": "{FIXTURE}",
                 "kind": "LocalServer32" if case == "patterns-localserver" else "InprocServer32",
                 "raw": str(registered) + (" -Embedding" if case == "patterns-localserver" else ""),
                 "view": "native"}] if case in ("patterns", "patterns-localserver") else [])
    report_path = outputs / "report.json"
    share_path = outputs / "sharing-summary.json"
    argv = ["--iocs", str(feed if case != "bad-feed" else inputs / "missing.txt"),
            "--json", str(report_path), "--share-json", str(share_path)]
    if target == "bundle":
        argv.append("--no-pause")
    if case == "quick":
        argv.append("--quick")
    if case == "workflow-handoff":
        argv.extend(["--report", str(outputs / "readable-saved.txt"),
                     "--evidence-bundle", str(outputs / "evidence.zip"),
                     "--evidence-file", str(files / "ordinary.dll")])
    if case in ("phone-process", "unicode-report", "ios-row-recovery", "android-intrusion", "ios-wal", "ios-sysdiagnose"):
        argv.extend(["--phone", str(phone)])
    if case == "ios-sysdiagnose":
        argv.extend(["--ios-input", "sysdiagnose"])
    if case == "windows-records":
        argv.extend(["--scan-type", "targeted", "--target", str(files)])
    if case in ("patterns", "patterns-localserver"):
        argv.append("--patterns")
    with contextlib.ExitStack() as stack:
        from reader_fixtures import stub_registered_readers
        from zbtriage import readers, netguard
        registry = cli if target == "bundle" else readers
        select_readers = registry.reader_select
        fixture_platform = "linux" if case == "linux-startup" else "darwin" if case == "macos-startup" else "win32"
        stack.enter_context(patch.object(registry, "reader_select", lambda ctx: select_readers(ctx, platform=fixture_platform)))
        extra_reader = ("windows-execution",) if case == "windows-records" else ("android-intrusion",) if case == "android-intrusion" else ("unix-host",) if case in ("linux-startup", "macos-startup") else ()
        native_traces = ("traces",) if sys.platform == "win32" or case.startswith("antivirus-") else ()
        stub_registered_readers(stack, cli if target == "bundle" else None,
                                keep=("browser", "hash", "host", "android", "ios", "patterns") + native_traces + extra_reader)
        if case in ("linux-startup", "macos-startup"):
            from zbtriage.modules import posix
            unix_reader = cli if target == "bundle" else posix
            check, kind = ("linux-autostart", "desktop") if case == "linux-startup" else ("macos-launch-items", "plist")
            stack.enter_context(patch.object(unix_reader, "_ux_roots", lambda: [(check, str(startup), kind)]))
        if target != "bundle":
            stack.enter_context(patch.object(netguard, "no_network", checked_network_guard))
        stack.enter_context(patch.object(cli, "no_network", checked_network_guard))
        for mod, name, value in (
                (browser, "CHROMIUM_ROOTS", [("fixture", str(profile.parent))]),
                (browser, "FIREFOX_ROOTS", []),
                (hashes, "_roots", lambda: [str(files)]),
                (patterns, "_pattern_roots", lambda: [str(files)]),
                (host, "winreg", object()),
                (host, "_ps_json", ps_json),
                # The hosts file is read on every platform; keep it in the fixture.
                (host, "_hosts_path", lambda: str(inputs / "System32" / "drivers" / "etc" / "hosts")),
                (host, "_enum_com_registrations", lambda r: (entries, [])),
                (host, "_dt_class_server", lambda hive, clsid: None),
                (host, "_network_drive_letters", lambda: (set(), True)),
                (host, "_user_writable_dirs", lambda: [str(inputs)]),
                (traces, "_tr_motw_roots", lambda: [str(files)]),
                (traces, "_tr_read_runmru", lambda: ({}, "", "")),
                (traces, "_tr_ran_programs", lambda: ([], {})),
                (traces, "_tr_events", lambda *a, **k: ([], "")),
                (traces, "_tr_antivirus_products", lambda: ([{"name": "Fixture antivirus", "state": 0, "signature_status": 1}], "")),
                (traces, "_tr_extra_history", lambda *a: None),
                (traces, "_tr_persistence", lambda *a: None),
                (reporting, "_platform_info", lambda: {"system": {"linux": "Linux", "darwin": "Darwin", "win32": "Windows"}[fixture_platform], "release": "fixture"})):
            stack.enter_context(patch.object(mod, name, value))
        if case.startswith("antivirus-"):
            # Real report/CLI behavior with authored OS responses on every host.
            def antivirus_fixture(context):
                result = traces.ModuleResult("traces")
                context.partial = result
                leads = traces._TrLeads(result)
                protection = traces._tr_check_antivirus(result, leads)
                traces._tr_check_defender(result, context, leads, protection)
                leads.finish()
                return result
            stack.enter_context(patch.object(traces, "run_traces" if target == "bundle" else "run", antivirus_fixture))
            stack.enter_context(patch.object(traces, "_tr_events", lambda log, *a, **k:
                ([{"Id": 5001, "Time": "2020-01-01", "Data": {}}], "") if log == traces._TR_DEFENDER_LOG else ([], "")))
            stack.enter_context(patch.object(traces, "_tr_antivirus_products", lambda:
                ([{"name": "Bitdefender", "state": 0, "signature_status": 1}], "") if case == "antivirus-active"
                else ([], "Security Center unavailable in fixture")))
        stack.enter_context(patch.object(host.platform, "system", return_value="Windows"))
        stdout, stderr = io.StringIO(), io.StringIO()
        # Do not let the CLI reconfigure the capture streams.
        stack.enter_context(patch.object(cli, "_force_utf8_io", lambda: None))
        sys.addaudithook(audit)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
    text = stdout.getvalue()
    (outputs / "report.txt").write_text(text, encoding="utf-8")
    require(not denied_activity, "blocked external activity occurred: " + str(denied_activity))
    require(snapshot(inputs) == before, "scanner changed fixture inputs")
    require(not list(scratch.iterdir()), "scanner left temporary snapshot files behind")
    require("PRIVATE_COOKIE_SENTINEL_DO_NOT_REPORT" not in text, "cookie value leaked to text")
    if case == "bad-feed":
        require(code == 1 and not report_path.exists(), "invalid feed must fail setup without a report")
        result = {"exit": code, "setup_error": True}
    else:
        doc = json.loads(report_path.read_text(encoding="utf-8"))
        shared_text = share_path.read_text(encoding="utf-8")
        shared = json.loads(shared_text)
        require(shared["report_type"] == "sharing-summary", "sharing summary missing")
        require(shared["exit_code"] == code, "sharing summary verdict differs")
        require(DOMAIN not in shared_text and str(inputs) not in shared_text
                and "PRIVATE_COOKIE_SENTINEL_DO_NOT_REPORT" not in shared_text,
                "private artifact data leaked into sharing summary")
        require("PRIVATE_COOKIE_SENTINEL_DO_NOT_REPORT" not in report_path.read_text(encoding="utf-8"),
                "cookie value leaked to JSON")
        modules, verdict = doc["modules"], doc["verdict"]
        hits = sorted((name, h["indicator"], h["evidence"])
                      for name, mod in modules.items() for h in mod["hits"])
        expected = {"contact": ("browser", DOMAIN, "contacted"),
                    "hit-and-gap": ("browser", DOMAIN, "contacted"),
                    "reference": ("browser", DOMAIN, "referenced"),
                    "hash": ("hash", DIGEST, "on-disk"),
                    "dns-cap-hit": ("host", DOMAIN, "dns-record")}
        expected["dns-off-retained-hit"] = ("host", DOMAIN, "dns-record")
        expected["phone-process"] = ("android", "com.release.fixture.spy", "on-device")
        expected["unicode-report"] = ("android", DIGEST, "on-device")
        expected["ios-row-recovery"] = ("ios", DOMAIN, "received")
        expected["ios-wal"] = ("ios", DOMAIN, "received")
        expected["ios-sysdiagnose"] = ("ios", "fixtureprocess", "device-log")
        if case in ("ios-wal", "ios-sysdiagnose"):
            provenance = modules["ios"]["hits"][0]["provenance"]
            require(provenance.get("sha256"), "source hash missing")
            require("provenance" not in shared_text, "sharing summary contains private provenance")
            require(provenance.get("wal_sha256") if case == "ios-wal" else provenance.get("member"),
                    "WAL or archive member provenance missing")
        expected["workflow-handoff"] = ("hash", DIGEST, "on-disk")
        if case == "workflow-handoff":
            require((outputs / "readable-saved.txt").read_text(encoding="utf-8").strip() == text.strip(),
                    "saved readable report differs from display")
            with zipfile.ZipFile(outputs / "evidence.zip") as archive:
                manifest = json.loads(archive.read("manifest.json"))
                require(not manifest["encrypted"], "export encryption claim incorrect")
                require(manifest["indicator_fingerprints"]["combined"] == doc["indicator_fingerprints"]["combined"],
                        "indicator fingerprint missing from handoff")
                require(archive.read("artifacts/0001.bin") == PAYLOAD, "selected original missing")
                for entry in manifest["files"]:
                    require(hashlib.sha256(archive.read(entry["member"])).hexdigest() == entry["sha256"], "handoff integrity mismatch")
                require(DOMAIN.encode() not in archive.read("sharing-summary.json"), "handoff summary leaks indicator")
        if case == "ios-row-recovery":
            require(modules["ios"]["skipped"] == 1, "unreadable message not counted")
            size_reason = "database field size limit" if hasattr(sqlite3.Connection, "setlimit") else "text limit"
            require(any(c["name"] == "ios:messages" and size_reason in c["reason"]
                        for c in modules["ios"]["checks"] if not c["ran"]), "specific message size gap missing")
        if case == "unicode-report":
            require(modules["android"]["hits"][0]["location"] == "/data/local/tmp/odd\ud800.dll",
                    "JSON lost the unusual filename or finding")
            require("odd\\ud800.dll" in text, "readable report lost the escaped filename")
            require(shared["verdict"]["findings_total"] == 1, "sharing summary lost the finding")
            text.encode("utf-8", "strict")
        if case == "phone-process":
            require(any(c["name"] == "android:processes" and c["ran"] for c in modules["android"]["checks"]),
                    "phone process check did not run")
            require(modules["android"]["submetrics"].get("android_processes") == 1, "phone process count missing")
        if case in ("patterns", "patterns-localserver") and engine:
            expected[case] = ("patterns", "yara:MAL_DevilsTongue_HijackDll", "file-pattern")
        expected_hits = ([expected[case]] if case in expected else [])
        if case == "history-host-reference":
            expected_hits = sorted([("browser", DOMAIN, "contacted"), ("browser", "sub." + DOMAIN, "referenced")])
        if case == "windows-records":
            expected_hits = [("windows-execution", "fixture-spy.exe", grade) for grade in ("execution-record", "inventory-record")]
        if case == "android-intrusion":
            expected_hits = sorted([("android-intrusion", DOMAIN, "dns-record"), ("android-intrusion", "203.0.113.8", "device-log")])
        if case in ("linux-startup", "macos-startup"):
            expected_hits = [("unix-host", "/opt/fixture-spy", "configured")]
        require(hits == expected_hits,
                "wrong evidence/hits: " + str(hits))
        require(verdict["hits_total"] == len(hits), "incorrect total finding count")
        expected_verdict = ("REFERENCES_ONLY" if case == "reference" else "INDICATORS_FOUND" if hits else
                            "NO_KNOWN_INDICATORS_WITH_GAPS" if case in
                            ("corrupt", "quick", "dns-cap-gap", "patterns", "patterns-localserver", "dns-off-retained-clean",
                             "dns-off-unreadable", "dns-off-empty", "antivirus-unknown") else "NO_KNOWN_INDICATORS")
        require(verdict["status"] == expected_verdict, "incorrect overall verdict: " + str(verdict))
        # Exit code follows the verdict (contract.EXIT_CODES): nothing found WITH
        # gaps is 3, never 0, so a script or AI cannot read missing checks as clean.
        expected_code = {"INDICATORS_FOUND": 2, "NO_KNOWN_INDICATORS": 0,
                         "REFERENCES_ONLY": 0,
                         "NO_KNOWN_INDICATORS_WITH_GAPS": 3}[expected_verdict]
        require(code == expected_code, "incorrect CLI exit code: {} (expected {})".format(
            code, expected_code))
        if case.startswith("antivirus-"):
            trace = modules["traces"]
            require(trace["submetrics"]["antivirus_products_on"] == int(case == "antivirus-active"),
                    "current antivirus state missing or incorrect")
            require(trace["submetrics"]["defender_protection_off_events"] == 1,
                    "historical Defender event was lost")
            require("Defender real-time protection was turned off" not in text,
                    "old Defender warning is still ambiguous")
            if case == "antivirus-active":
                require("Bitdefender" in text and not trace["leads"], "active replacement was not contextualized")
            else:
                require(any(c["name"] == "antivirus-status" and not c["ran"] for c in trace["checks"]),
                        "unavailable antivirus state was called checked")
        if case == "reference":
            require("preserve" not in [x["id"] for x in doc["must_relay"]],
                    "saved reference incorrectly requires preservation")
        if case.startswith("dns-cap-"):
            require(any("dns-log-older-events" in g for g in verdict["gaps"]), "missing DNS cap gap")
            require(modules["host"]["submetrics"]["dns_log_events_scanned"] == 50000, "wrong DNS count")
            require('this machine holds no' not in text, 'unread history misreported as absent')
            require('reported by this scan' in text, 'reach statement is not scoped to scan')
        if case.startswith("dns-off-"):
            require(modules["host"]["submetrics"]["dns_log_enabled"] == 0, "logging state misreported")
            require(bool(verdict["gaps"]), "disabled logging coverage gap missing")
        if case.startswith("dns-off-retained-"):
            require(modules["host"]["submetrics"]["dns_log_events_scanned"] == 1, "retained event not searched")
            require("HOW TO TURN ON DNS HISTORY" in text, "future-logging instructions missing")
        if case in ("dns-off-empty", "dns-off-unreadable"):
            require(not modules["host"]["submetrics"].get("dns_log_events_scanned"), "unread log falsely searched")
        if case == "quick":
            require(modules["hash"]["status"] == "UNKNOWN", "quick scan falsely cleared file hashes")
        if case in ("corrupt", "hit-and-gap"):
            require(any("history" in g for g in verdict["gaps"]), "corrupt database gap missing")
        if case in ("contact", "hit-and-gap"):
            require(str(cookie) in text, "human report lost the full cookie file path")
        if case in ("patterns", "patterns-localserver"):
            require(modules["patterns"]["status"] == ("HITS" if engine else "UNKNOWN"),
                    "optional engine status is dishonest")
        if case in ("windows-records", "linux-startup", "macos-startup"):
            require("execution" in text.lower() and text.strip(), "new evidence interpretation missing from readable report")
        else:
            require(("phone evidence only" if case in ("phone-process", "unicode-report", "ios-row-recovery", "android-intrusion", "ios-wal", "ios-sysdiagnose") else "HOW FAR BACK THIS SCAN COULD SEE") in text,
                    "human report did not render")
        result = {"exit": code, "verdict": verdict["status"], "hits": hits,
                  "modules": {n: m["status"] for n, m in modules.items()},
                  "gaps": sorted(g.split(":", 1)[0] for g in verdict["gaps"])}
    (root / "result.json").write_text(json.dumps(result), encoding="utf-8")
    print("PASS {} {}: inputs unchanged, expected report/exit, no external activity".format(target, case))


if __name__ == "__main__":
    main()
