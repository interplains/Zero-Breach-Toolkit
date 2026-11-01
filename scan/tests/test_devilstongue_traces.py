"""Candiru DevilsTongue: published file locations and hijacked COM classes
(Microsoft 2021, Avast 2022) are reported as leads to check, never findings,
and a normal Windows machine produces none."""
import os

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet
from zbtriage.modules import host
from zbtriage.result import ModuleResult


def _run(monkeypatch, tmp_path, servers):
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setattr(host, "_dt_class_server", lambda hive, clsid: servers.get((hive, clsid)))
    r = ModuleResult("host")
    host._check_devilstongue(r, ScanContext(IocSet([], "x", None), emit=lambda _m: None))
    return r


def _normal():
    return {("HKLM", clsid): os.path.join("C:", "Windows", "system32", "wbem", name)
            for clsid, name in host._DT_CLASSES.items()}


def test_normal_machine_has_no_leads(monkeypatch, tmp_path):
    r = _run(monkeypatch, tmp_path, _normal())
    assert r.leads == [] and r.hits == []
    assert [c.name for c in r.checks if c.ran] == ["devilstongue-traces"]


def test_planted_file_is_a_lead_not_a_finding(monkeypatch, tmp_path):
    target = tmp_path.joinpath("System32", "drivers")
    target.mkdir(parents=True)
    (target / "physmem.sys").write_bytes(b"x")
    r = _run(monkeypatch, tmp_path, _normal())
    assert r.hits == [] and len(r.leads) == 1
    assert r.leads[0].location.endswith("physmem.sys") and "signature" in r.leads[0].usual_reason


@pytest.mark.parametrize("hive", ["HKLM", "HKCU"])
def test_hijacked_class_is_a_lead(monkeypatch, tmp_path, hive):
    servers = _normal()
    clsid = "{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}"
    servers[(hive, clsid)] = os.path.join("C:", "Windows", "system32", "ime", "SHARED", "imecpmeid.dll")
    r = _run(monkeypatch, tmp_path, servers)
    assert r.hits == [] and len(r.leads) == 1
    assert clsid in r.leads[0].location and r.leads[0].location.startswith(hive)
