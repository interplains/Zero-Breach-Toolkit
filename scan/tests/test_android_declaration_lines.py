"""Manifest declaration lines in dumpsys package are not a trace of an installed app."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import android
from zbtriage.result import ModuleResult
from test_evidence_safety import _ctx
from test_followup_fixes import bundle


@pytest.fixture(params=("source", "bundle"))
def android_api(request, bundle):
    return android if request.param == "source" else bundle


def _run(api, tmp_path, dumpsys):
    ctx = _ctx()
    ctx.iocs = IocSet([
        Indicator("com.microsoft.familysafety", "artifact", "primary", "app-id", "fixture"),
        Indicator("com.stalker.fixture", "artifact", "primary", "app-id", "fixture"),
        Indicator("declared.invalid", "infrastructure", "primary", "domain", "fixture"),
    ], "fixture", None)
    (tmp_path / "dumpsys.txt").write_text(dumpsys)
    (tmp_path / "logcat.txt").write_text("")
    result = ModuleResult("android") if api is android else api.ModuleResult("android")
    api._an_device_logs(result, ctx, str(tmp_path), set())
    return {h.indicator for h in result.hits}


HEAD = "DUMP OF SERVICE package:\nPackages:\n  Package [com.microsoft.office.outlook] (abc):\n"


@pytest.mark.parametrize("key", (
    "queriesPackages", "queriesProviders", "queriesIntents", "usesLibraries",
    "usesOptionalLibraries", "usesStaticLibraries", "usesSdkLibraries"))
def test_declared_app_ids_are_not_reported(tmp_path, android_api, key):
    line = "    {}=[com.android.vending, com.microsoft.familysafety, com.whatsapp]\n".format(key)
    assert _run(android_api, tmp_path, HEAD + line) == set()


def test_real_package_record_is_still_reported(tmp_path, android_api):
    text = (HEAD + "    queriesPackages=[com.android.vending, com.microsoft.familysafety, com.whatsapp]\n"
            "  Package [com.stalker.fixture] (def):\n")
    assert _run(android_api, tmp_path, text) == {"com.stalker.fixture"}


def test_domains_on_declaration_lines_are_still_searched(tmp_path, android_api):
    text = HEAD + "    queriesProviders=[declared.invalid]\n"
    assert _run(android_api, tmp_path, text) == {"declared.invalid"}
