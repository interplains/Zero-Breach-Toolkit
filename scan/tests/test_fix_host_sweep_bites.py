"""Guard against a vacuous sweep: every unusable-input case in sweep_host.py must leave a
gap (a check that did not run) for the check it targets, so "no ran" cannot pass because the
reader never looked. The few cases where an unrelated or schema-drifted store is deliberately
just not marked are listed with the reason."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_host

NOT_MARKED_ON_PURPOSE = {
    ("download-chains", "History without a downloads_url_chains table"):
        "a Chromium History from before download chains is schema drift: not marked, no gap",
}


# Where a reader records the gap under another name than the check it could not complete.
GAP_NAME = {"known-paths": "known-path:", "android-intrusion:dns": "android-intrusion:files",
            "android-intrusion:connections": "android-intrusion:files",
            "android-intrusion:processes": "android-intrusion:files"}


def _cases():
    for name, cases in sorted(sweep_host.UNUSABLE.items()):
        for case_id, factory in cases:
            yield pytest.param(name, case_id, factory, id="{}:{}".format(name, case_id))


@pytest.mark.parametrize("name,case_id,factory", list(_cases()))
def test_every_unusable_case_leaves_a_gap(name, case_id, factory, tmp_path):
    if (name, case_id) in NOT_MARKED_ON_PURPOSE:
        pytest.skip(NOT_MARKED_ON_PURPOSE[(name, case_id)])
    result = factory(tmp_path)
    prefix = GAP_NAME.get(name, name)
    gaps = [c for c in result.checks if not c.ran and c.name.startswith(prefix)]
    assert gaps, "{} / {}: no gap was recorded; checks were {}".format(
        name, case_id, [(c.name, c.ran) for c in result.checks])
