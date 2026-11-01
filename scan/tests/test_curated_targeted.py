"""The curated set of spyware used against journalists, activists and minorities
(iocs/curated_targeted.txt), and the declared-kind column it needs for Android
package names."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from zbtriage import cli  # noqa: E402
from zbtriage.iocs import (IocError, TYPE_APP_ID, TYPE_DOMAIN, TYPE_SHA256, load,  # noqa: E402
                           load_any, merge)

TARGETED = os.path.join(REPO, "iocs", "curated_targeted.txt")
GENERATOR = os.path.join(REPO, "tools", "gen_curated_targeted.py")
OTHERS = [os.path.join(REPO, "iocs", n) for n in ("adfection_iocs.txt", "curated_mercenary.txt")]

# One fingerprint per source, copied from the publisher's file.
ONE_HASH_PER_SOURCE = {
    "eset-aridspy-2024-06": "0cb41557841ff6f314c398250a165706e0b18f93674a7c12f4489018a1661673",
    "talos-aridviper-2023-10": "d69cf49f703409bc01ff188902d88858a6237a2b4b0124d553a9fc490e8df68a",
    "meta-palestine-2021-04": "05320c7348c156f0a98907d2b1527ff080eae36437d58735f2822d9f42f5d273",
    "volexity-evilbamboo-2023-09": "b7c1a56d3e817bfa47d540f37dc45441325e81332e4c71a5e65d7de67b8f4b3c",
    "volexity-uta0560-2026-09": "d17053557bb90298f7b115432b4820a248fdbe678bca31721529b1f51a82343b",
    "unit42-henbox-2018-03": "f3d04a7f77498acec86efc8d372c4d6eac591d8030f0a867ab856074e4da1fe6",
    "lookout-plaingnome-2024-12": "2c7827f92a103db1b299f334043fbdc73805bbee11f4bfac195f672ba0464d22",
    "eset-kamran-2023-11": "016c602caf1731d2d53e7f93dd41c04b26778a65c5c27e64a2f0c2c8d5fb87e0",
    "eset-scarcruft-dolphin-2022-11": "486bd76669fc2c0adc25a5498b42c1df5fc90514866d78318f8954aa0c67eacc",
    "eset-scarcruft-birdcall-2026-05": "415b253a81e67c8c860a97c73edc9017ce732b3c025d943d3b1a445b4ac82822",
    "volexity-brazenbamboo-2024-11": "666a4c569d435d0e6bf9fa4d337d1bf014952b42cc6d20e797db6c9df92dd724",
    "lookout-bonespy-2024-12": "114d2a25bb4c296f8ef5bfca4e8192b5aca9b169099ac6291139e68cfc7e37dc",
    "eset-ghostchat-2026-01": "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb",
    "eset-vajraspy-2024-01": "c547fc04afad7538be1c638019867145dabf630afc2eba1ece7f972892598a65",
    "eset-exoticvisit-2024-03": "47d6d9b52bfed7481c9db51712e4a81c6f773efa1d96ac2c0d71dc0f6f6ddd6a",
    "eset-gravityrat-2023-06": "caf0a39318cfc1e65eae773a28de62ce08b7cf1b9d4264e843576165411e2a84",
    "eset-dazzlespy-2022-01": "bbbfe62cf15006014e356885fbc7447e3fd37c3743e0522b1f8320ad5c3791c9",
    "amnesty-donot-togo-2021-10": "000ddbb75d10a939b54a7ceea5f12563b855daec971a9da0f2b4d5f935e195a3",
    "amnesty-oceanlotus-vietnam-2021-02": "952c16674bde3c16aa3935b3e01f3f0fb4cbac7ffa130143cbf6ccaa72733068",
    "amnesty-netwire-india-2020-06": "e3dea449bf74434ee1c9cdc04ca68b8f3c9bac357768e07df303433f257d3b9a",
}

# Rows per source and kind. A change here is a reviewed decision, not a quiet edit.
EXPECTED_COUNTS = {
    ("eset-aridspy-2024-06", TYPE_SHA256): 15, ("eset-aridspy-2024-06", TYPE_APP_ID): 3,
    ("talos-aridviper-2023-10", TYPE_SHA256): 15, ("sentinel-spyc23-2023-10", TYPE_APP_ID): 2,
    ("meta-palestine-2021-04", TYPE_SHA256): 14,
    ("volexity-evilbamboo-2023-09", TYPE_SHA256): 212,
    ("volexity-uta0560-2026-09", TYPE_SHA256): 19,
    ("volexity-brazenbamboo-2024-11", TYPE_SHA256): 57,
    ("unit42-henbox-2018-03", TYPE_SHA256): 215, ("unit42-henbox-2018-03", TYPE_APP_ID): 8,
    ("lookout-bonespy-2024-12", TYPE_SHA256): 28, ("lookout-plaingnome-2024-12", TYPE_SHA256): 8,
    ("eset-ghostchat-2026-01", TYPE_SHA256): 2,
    ("eset-kamran-2023-11", TYPE_SHA256): 1, ("eset-kamran-2023-11", TYPE_APP_ID): 1,
    ("eset-vajraspy-2024-01", TYPE_SHA256): 13, ("eset-exoticvisit-2024-03", TYPE_SHA256): 20,
    ("eset-gravityrat-2023-06", TYPE_SHA256): 3, ("eset-gravityrat-2023-06", TYPE_APP_ID): 2,
    ("eset-dazzlespy-2022-01", TYPE_SHA256): 3,
    ("eset-scarcruft-dolphin-2022-11", TYPE_SHA256): 5,
    ("eset-scarcruft-birdcall-2026-05", TYPE_SHA256): 9,
    ("amnesty-donot-togo-2021-10", TYPE_SHA256): 228,
    ("amnesty-oceanlotus-vietnam-2021-02", TYPE_SHA256): 14,
    ("amnesty-netwire-india-2020-06", TYPE_SHA256): 12,
}

# SHA-256 of identifiers of sources that were reviewed and not taken. No token of
# the file (values, tags, families or header text) may be one of them.
_NOT_TAKEN = frozenset((
    "d75183dd16482423c46b7901593260f43f9c6c2237f27e992747e1387d3d9474",
    "2d534d48700b2455ac17b7356b0a4573cee154b8951d6dc296bdc26ed17e966e",
    "935d81f41521cb3c15178ac78a8b4a38449076264021af1c3e51398a2d845820",
    "04e3a8ffd36b16077ea6fc6494ef086f6a207e10a1006144068b5e277be09b2a",
    "3fc81a2348ee6614856d39e6fc60a7308cbeab7cf222f1e03e1d1b70c6661dd9",
    "a23061616678f32f71b5201d89298ba7ac5e454d0ef3192b6d644f091dc943b6",
    "f84a347034749ea1db6249ac32a33eeba554c3b9a391a3bbc05826bf4a243261",
    "ba2436bd25a09dd572c044797e6978eaa9c498fb36fa0f59fb672ca03cc3faf7",
    "ed149fce28b15b996301b230030053e6b9d81e14337606856e913f4f35a5bb86",
    "6038ac4d789347a54e09f7f4e1103733da8ebbf5cdb29b2834d3ccecb2dac7aa",
    "6d4b9ee62028b80981988484e790bac1fdd5a9eb9f30022c6268397e5dd2b79f",
    "93ddd9b5aea5e154793073c7449b845878af058e7c227566f478f53aef7a8b29",
    "3d36b194a804e29fc2d6594d8040ad480090c36cb0bfecc620fefc8919138d51",
    "2593301634791351658a522995259b2b73e2ea0f5ad075430c12b9331885c480",
    "8fbf7a0e957664c0e067e09345d2719b5c9dcbb2467d3f273cf48929ac7d4aeb",
    "1f49185e27593c57652c9f5afaca6d1325f6c70db8e28938051e36766defc143",
    "218f100a173e80a98360dc94417fffb162e3cbe77d36988b0dc4c9f74a9367e4",
    "62930948df1b23e97e0692a0b9fe8a308c99392e81bba3dba40f6fe80d3184a5",
))


def _rows(text):
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            yield line.split("\t")


class TestCuratedTargeted(unittest.TestCase):
    def setUp(self):
        self.text = io.open(TARGETED, encoding="utf-8").read()
        self.set = load(TARGETED)

    def test_generator_reproduces_the_file_exactly(self):
        out = os.path.join(tempfile.mkdtemp(prefix="gen_"), "x.txt")
        subprocess.run([sys.executable, "-I", GENERATOR, out], check=True, capture_output=True)
        self.assertEqual(io.open(out, encoding="utf-8").read(), self.text)

    def test_has_an_as_of_date(self):
        self.assertEqual(self.set.asof, "2026-11-01")

    def test_every_row_is_cited_and_has_a_family(self):
        documented = set(re.findall(r"^#\s{3}([a-z][a-z0-9-]+)\s{2}", self.text, re.M))
        for ind in self.set.indicators:
            with self.subTest(indicator=ind.value):
                self.assertIn(ind.source, documented)
                self.assertTrue(ind.family)
                self.assertEqual(ind.confidence, "primary")

    def test_counts_per_source_and_kind(self):
        got = {}
        for ind in self.set.indicators:
            got[(ind.source, ind.type)] = got.get((ind.source, ind.type), 0) + 1
        self.assertEqual(got, EXPECTED_COUNTS)
        self.assertEqual(len(self.set.indicators), 909)

    def test_only_fingerprints_and_package_names(self):
        for ind in self.set.indicators:
            with self.subTest(indicator=ind.value):
                self.assertIn(ind.type, (TYPE_SHA256, TYPE_APP_ID))
                if ind.type == TYPE_SHA256:
                    self.assertRegex(ind.value, r"^[0-9a-f]{64}$")
                    self.assertEqual(ind.tier, "sample")
                else:
                    self.assertRegex(ind.value, r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
                    self.assertEqual(ind.tier, "artifact")
        self.assertEqual(self.set.domains, [])
        self.assertEqual(self.set.ips, [])

    def test_no_duplicate_rows(self):
        keys = [(r[5] if len(r) > 5 else "", r[0]) for r in _rows(self.text)]
        self.assertEqual(len(keys), len(set(keys)))

    def test_a_published_fingerprint_from_each_source_is_matched(self):
        self.assertEqual(set(ONE_HASH_PER_SOURCE),
                         {src for src, kind in EXPECTED_COUNTS if kind == TYPE_SHA256})
        for source, value in ONE_HASH_PER_SOURCE.items():
            with self.subTest(source=source):
                ind = self.set.lookup_typed(TYPE_SHA256, value)
                self.assertIsNotNone(ind)
                self.assertEqual(ind.source, source)

    def test_package_names_are_matched_as_package_names_not_domains(self):
        for name, family in (("com.chat.lapiza", "Arid Viper (AridSpy)"),
                             ("com.teleram.app", "Arid Viper (SpyC23)"),
                             ("com.android.henbox", "HenBox"),
                             ("com.kamran.hunzanews", "Kamran"),
                             ("eu.siacs.bingechat", "GravityRAT")):
            with self.subTest(name=name):
                ind = self.set.lookup_typed(TYPE_APP_ID, name)
                self.assertIsNotNone(ind)
                self.assertEqual(ind.family, family)
                self.assertIsNone(self.set.lookup_typed(TYPE_DOMAIN, name))
        self.assertNotIn("com.chat.lapiza", self.set.network_strings)

    def test_generic_and_real_app_names_are_left_out(self):
        # Another developer could use these names, or they belong to the real app
        # the spyware repackaged; their samples are matched by fingerprint instead.
        for name in ("com.app.workapp", "com.studio.manager.app", "com.weather.services.manager",
                     "com.jrzheng.supervpn.view", "cn.android.setting", "cn.android.seting",
                     "cx.ring"):
            with self.subTest(name=name):
                self.assertIsNone(self.set.lookup_typed(TYPE_APP_ID, name))

    def test_no_value_repeats_one_already_shipped(self):
        for path in OTHERS:
            other = {(i.type, i.value) for i in load(path).indicators}
            with self.subTest(path=os.path.basename(path)):
                self.assertFalse(other & {(i.type, i.value) for i in self.set.indicators})

    def test_sources_not_taken_are_absent(self):
        tokens = set(re.split(r"[^a-z0-9_-]+", self.text.lower())) - {""}
        hashed = {hashlib.sha256(t.encode("ascii", "ignore")).hexdigest() for t in tokens}
        self.assertFalse(hashed & _NOT_TAKEN)


class TestShippedDefaults(unittest.TestCase):
    def test_default_files_include_the_new_set_and_lose_nothing(self):
        paths = cli._default_ioc_paths()
        self.assertEqual([os.path.basename(p) for p in paths],
                         ["adfection_iocs.txt", "curated_mercenary.txt", "curated_targeted.txt"])
        merged = merge([load_any(p) for p in paths])
        for path in paths:
            for ind in load(path).indicators:
                got = merged.lookup_typed(ind.type, ind.value)
                self.assertIsNotNone(got, ind.value)
                self.assertEqual((got.tier, got.confidence), (ind.tier, ind.confidence))
        ind = merged.lookup_typed(TYPE_SHA256, ONE_HASH_PER_SOURCE["eset-aridspy-2024-06"])
        self.assertEqual(ind.family, "Arid Viper (AridSpy)")


class TestAndroidCollectionWithShippedSets(unittest.TestCase):
    def test_package_name_and_app_file_fingerprint_are_found(self):
        from zbtriage.context import ScanContext
        from zbtriage.modules import android
        merged = merge([load_any(p) for p in cli._default_ioc_paths()])
        henbox = ONE_HASH_PER_SOURCE["unit42-henbox-2018-03"]
        d = tempfile.mkdtemp(prefix="aqf_")
        pkgs = [{"name": "com.kamran.hunzanews", "installer": "com.android.packageinstaller",
                 "third_party": True, "system": False, "disabled": False, "uid": 1,
                 "files": [{"path": "/data/app/k/base.apk", "sha256": henbox,
                            "certificate": {"Sha256": "e" * 64, "Sha1": "e" * 40}}]},
                {"name": "com.jrzheng.supervpn.view", "installer": "com.android.vending",
                 "third_party": True, "system": False, "disabled": False, "uid": 2,
                 "files": []}]
        for name, data in (("packages.json", pkgs), ("files.json", []), ("root_binaries.json", []),
                           ("acquisition.json", {"started": "2026-11-01T00:00:00Z"})):
            with io.open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        with io.open(os.path.join(d, "getprop.txt"), "w", encoding="utf-8") as fh:
            fh.write("[ro.build.version.security_patch]: [2099-01-01]\n")
        r = android.run(ScanContext(iocs=merged, emit=lambda _m: None, phone_path=d))
        got = {(h.indicator, h.family) for h in r.hits}
        self.assertEqual(got, {("com.kamran.hunzanews", "Kamran"), (henbox, "HenBox")})


class TestDeclaredKindColumn(unittest.TestCase):
    def _load(self, body):
        path = os.path.join(tempfile.mkdtemp(prefix="kind_"), "x.txt")
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# as-of: 2026-11-01\n" + "a" * 64 + "\tsample\tprimary\tsrc\tFam\n" + body)
        return load(path)

    def test_package_name_column(self):
        s = self._load("org.example.app\tartifact\tprimary\tsrc\tFam\tapp-id\n")
        self.assertIsNotNone(s.lookup_typed(TYPE_APP_ID, "org.example.app"))
        self.assertIsNone(s.lookup_typed(TYPE_DOMAIN, "org.example.app"))

    def test_same_string_as_package_name_and_domain_keeps_both(self):
        s = self._load("org.example.app\tartifact\tprimary\tsrc\tFam\tapp-id\n"
                       "org.example.app\tinfrastructure\tprimary\tsrc\tFam\n")
        self.assertIsNotNone(s.lookup_typed(TYPE_APP_ID, "org.example.app"))
        self.assertIsNotNone(s.lookup_typed(TYPE_DOMAIN, "org.example.app"))

    def test_only_package_names_and_certificates_may_be_declared(self):
        for bad in ("org.example.app\tartifact\tprimary\tsrc\tFam\tdomain\n",
                    "org.example.app\tartifact\tprimary\tsrc\tFam\tprocess\n",
                    "Org.Example App\tartifact\tprimary\tsrc\tFam\tapp-id\n",
                    "nodot\tartifact\tprimary\tsrc\tFam\tapp-id\n",
                    "abcd\tartifact\tprimary\tsrc\tFam\tapp-cert\n"):
            with self.subTest(row=bad):
                with self.assertRaises(IocError):
                    self._load(bad)


if __name__ == "__main__":
    unittest.main()
