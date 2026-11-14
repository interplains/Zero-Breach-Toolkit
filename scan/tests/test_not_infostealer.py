"""This tool must stay distinguishable from the malware it resembles.

The scanner opens browser cookie databases, fingerprints tens of thousands of
files and enumerates the registry. An infostealer does all three. The difference
is one specific thing: an infostealer DECRYPTS the cookie values, because the
values are the credentials it is stealing. This tool only ever reads cookie
HOST NAMES and metadata, which is all that indicator matching needs.

That distinction is the whole basis on which an antivirus analyst, a reviewer, or
a cautious user can tell us apart from a credential thief - so it is asserted
here rather than merely promised in a README. If a future change starts reading
encrypted values or calling Windows' decryption APIs, this suite fails.
"""

from __future__ import annotations

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "zbtriage")


def _pure_data(text):
    """True when a module is nothing but a docstring and assignments of literal values (no imports, calls,
    functions or classes): generated lists such as extensiondata.py, whose random extension IDs can spell a
    forbidden word by chance. Nothing executable can hide in such a file, so it is not text-searched."""
    import ast
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        if isinstance(node, ast.Assign):
            try:
                ast.literal_eval(node.value)
            except ValueError:
                return False
            continue
        return False
    return True


def source_files():
    for root, _dirs, files in os.walk(PKG):
        for fn in files:
            if fn.endswith(".py"):
                path = os.path.join(root, fn)
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                if fn.endswith("data.py") and _pure_data(text):
                    continue
                yield os.path.relpath(path, PKG), text


class TestNeverDecryptsSecrets(unittest.TestCase):
    def test_no_module_reads_encrypted_cookie_values(self):
        offenders = []
        for name, text in source_files():
            low = text.lower()
            for needle in ("encrypted_value", "encrypted_key", "value_encrypted"):
                if needle in low:
                    offenders.append("{}: {}".format(name, needle))
        self.assertEqual(
            offenders, [],
            "reading encrypted cookie/credential values is what an infostealer "
            "does; indicator matching only needs the host name: {}".format(offenders))

    def test_no_module_calls_a_decryption_api(self):
        # DPAPI and the AES-GCM unwrap of Chromium's local state key are the
        # specific mechanisms credential stealers use on Windows.
        # NOTE on "Local State": that file is read, deliberately, for profile
        # DISPLAY NAMES. It is also where Chromium keeps the encrypted master
        # key for cookie values, so reading the file is step one of credential
        # theft - which is why `os_crypt` and `encrypted_key` stay banned below,
        # and why test_local_state_master_key_is_never_read asserts
        # behaviourally that the key never reaches the output. Reading the file
        # is allowed; reading the key is not.
        forbidden = ("cryptunprotectdata", "dpapi", "win32crypt", "protect_data",
                     "aesgcm", "aes_gcm", "unprotect", "os_crypt",
                     "encrypted_key")
        offenders = []
        for name, text in source_files():
            low = text.lower()
            for needle in forbidden:
                if needle in low:
                    offenders.append("{}: {}".format(name, needle))
        self.assertEqual(offenders, [],
                         "no module may touch a credential-decryption path: {}"
                         .format(offenders))

    def test_no_crypto_library_imported(self):
        pattern = re.compile(
            r"^\s*(?:import|from)\s+(cryptography|Crypto|nacl|pycryptodome)\b",
            re.MULTILINE)
        offenders = [name for name, text in source_files() if pattern.search(text) and name != "backupcrypto.py"]
        self.assertEqual(offenders, [],
                         "only backupcrypto.py may decrypt owner-supplied phone backups: "
                         "{}".format(offenders))

    ALLOWED_COOKIE_COLUMNS = {
        "host_key", "name", "host", "creation_utc", "creationtime",
        "top_frame_site_key", "last_access_utc", "lastaccessed", "expires_utc",
    }

    def test_cookie_column_allowlist_is_narrow(self):
        """The columns the module is willing to ask for are built from literal
        lists, so those lists are the thing to pin. Widening them has to be a
        deliberate act that fails this test first."""
        import ast

        path = os.path.join(PKG, "modules", "browser.py")
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not any(getattr(t, "id", "") == "candidates" for t in node.targets):
                continue
            if not isinstance(node.value, ast.List):
                continue
            cols = [e.value.lower() for e in node.value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            found.append(cols)
            for col in cols:
                self.assertIn(
                    col, self.ALLOWED_COOKIE_COLUMNS,
                    "cookie column {!r} is not on the allow-list - reading more "
                    "of a cookie store than host/name/timestamps needs a "
                    "deliberate decision".format(col))
        self.assertGreaterEqual(
            len(found), 2,
            "expected the Chromium and Firefox cookie column lists")

    def test_an_encrypted_cookie_value_is_never_read(self):
        """Behavioural proof, which is stronger than reading the source: give the
        module a cookie database whose encrypted_value holds a sentinel, and the
        sentinel must appear nowhere in anything the module produces."""
        import sqlite3
        import sys
        import tempfile

        sys.path.insert(0, os.path.dirname(PKG))
        from zbtriage import iocs as iocmod
        from zbtriage.context import ScanContext
        from zbtriage.modules import browser

        sentinel = b"SENTINEL-SECRET-VALUE-DO-NOT-READ"
        tmp = tempfile.mkdtemp(prefix="nostealer_")
        net = os.path.join(tmp, "User Data", "Default", "Network")
        os.makedirs(net)
        con = sqlite3.connect(os.path.join(net, "Cookies"))
        con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                    "encrypted_value BLOB, value TEXT, creation_utc INTEGER)")
        con.execute("INSERT INTO cookies VALUES (?, 'sid', ?, ?, 13300000000000000)",
                    (".synthetic-test-indicator.invalid", sentinel,
                     sentinel.decode()))
        con.commit()
        con.close()

        ioc_path = os.path.join(tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("synthetic-test-indicator.invalid\tdelivery\tprimary\tt\n")
        ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)

        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                 browser.FIREFOX_ROOTS)
        try:
            browser.CHROMIUM_ROOTS = [("test", os.path.join(tmp, "User Data"))]
            browser.ROAMING = empty
            browser.LOCAL = empty
            browser.FIREFOX_ROOTS = []
            result = browser.run(ctx)
        finally:
            (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
             browser.FIREFOX_ROOTS) = saved

        # The indicator must still be found - we are not testing that it reads
        # nothing, only that it never reads the secret.
        self.assertTrue(result.hits, "the cookie host should still match")
        blob = repr(result.to_dict())
        self.assertNotIn(sentinel.decode(), blob,
                         "the cookie's encrypted_value leaked into the result")
        self.assertNotIn("SENTINEL", blob.upper(),
                         "no part of a cookie's value may reach the output")


class TestLocalStateMasterKey(unittest.TestCase):
    """Local State is read for profile display names. The same file holds the
    encrypted master key for cookie values, so prove the key is never taken."""

    def test_local_state_master_key_is_never_read(self):
        import json
        import sqlite3
        import sys
        import tempfile

        sys.path.insert(0, os.path.dirname(PKG))
        from zbtriage import iocs as iocmod
        from zbtriage.context import ScanContext
        from zbtriage.modules import browser

        key_sentinel = "MASTER-KEY-SENTINEL-MUST-NOT-APPEAR"
        tmp = tempfile.mkdtemp(prefix="localstate_")
        ud = os.path.join(tmp, "User Data")
        net = os.path.join(ud, "Profile 1", "Network")
        os.makedirs(net)

        with open(os.path.join(ud, "Local State"), "w", encoding="utf-8") as fh:
            json.dump({
                "os_crypt": {"encrypted_key": key_sentinel},
                "profile": {"info_cache": {
                    "Profile 1": {"name": "Work",
                                  "user_name": "someone@example.invalid",
                                  "gaia_name": "Someone Real"}}},
            }, fh)

        con = sqlite3.connect(os.path.join(net, "Cookies"))
        con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                    "creation_utc INTEGER)")
        con.execute("INSERT INTO cookies VALUES "
                    "('.synthetic-test-indicator.invalid', 'uid', 13300000000000000)")
        con.commit()
        con.close()

        ioc_path = os.path.join(tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("synthetic-test-indicator.invalid\tdelivery\tprimary\tt\n")
        ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)

        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                 browser.FIREFOX_ROOTS)
        try:
            browser.CHROMIUM_ROOTS = [("test", ud)]
            browser.ROAMING = empty
            browser.LOCAL = empty
            browser.FIREFOX_ROOTS = []
            result = browser.run(ctx)
        finally:
            (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
             browser.FIREFOX_ROOTS) = saved

        blob = repr(result.to_dict())
        self.assertNotIn(key_sentinel, blob,
                         "the cookie-decryption master key leaked into the result")
        # The display name is the thing we DO want, so prove it arrived.
        self.assertTrue(any(h.profile and "Work" in h.profile
                            for h in result.hits),
                        "the profile display name should be attached to the hit")
        # And the signed-in email must not be collected along with it.
        self.assertNotIn("someone@example.invalid", blob,
                         "the signed-in email address must not be collected")
        self.assertNotIn("Someone Real", blob,
                         "only the profile display name is collected")


class TestReadOnly(unittest.TestCase):
    def test_no_module_opens_a_file_for_writing(self):
        """Modules may only read. The one legitimate write - a temp copy of a
        locked database - goes through shutil.copy2, not an open-for-write."""
        pattern = re.compile(r"""open\([^)]*['"][rwax+b]*[wa+]['"]""")
        offenders = []
        for name, text in source_files():
            if not name.startswith("modules"):
                continue
            if pattern.search(text):
                offenders.append(name)
        self.assertEqual(offenders, [],
                         "scan modules must not write files: {}".format(offenders))

    def test_no_module_writes_to_the_registry(self):
        forbidden = ("setvalue", "createkey", "deletekey", "deletevalue",
                     "savekey", "set-itemproperty", "new-itemproperty",
                     "remove-item")
        offenders = []
        for name, text in source_files():
            if not name.startswith("modules"):
                continue
            low = text.lower()
            for needle in forbidden:
                if needle in low:
                    offenders.append("{}: {}".format(name, needle))
        self.assertEqual(offenders, [],
                         "scan modules are read-only; writing belongs to --arm "
                         "alone: {}".format(offenders))


if __name__ == "__main__":
    unittest.main(verbosity=2)
