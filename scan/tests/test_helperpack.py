"""Package for a helper: sealed so only the helper's age key opens it, signed so the helper knows who sent it,
AndroidQF collections kept as they are, tampering detected, no plaintext left on disk, nothing sent anywhere."""
import io
import json
import os
import socket
import zipfile

import pytest

from zbtriage import ageseal as ag
from zbtriage import helperpack as hp


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("making a package must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.fixture
def helper():
    identity = os.urandom(32)
    return identity, ag.ag_encode_recipient(ag.ag_x25519(identity, ag.AG_X25519_BASE))


def _evidence(tmp_path):
    src = tmp_path / "evidence"
    (src / "screens").mkdir(parents=True)
    (src / "report.json").write_text('{"verdict": "worth a look"}', encoding="utf-8")
    (src / "screens" / "sms.png").write_bytes(os.urandom(5000))
    big = tmp_path / "capture.pcap"
    big.write_bytes(os.urandom(200_000))
    return [str(src), str(big)]


def _open(path, identity):
    from test_ageseal import _age_decrypt
    with open(path, "rb") as fh:
        return zipfile.ZipFile(io.BytesIO(_age_decrypt(fh.read(), identity)))


def test_sealed_package_opens_only_with_the_helper_key_and_verifies(tmp_path, helper):
    identity, recipient = helper
    out = tmp_path / "out"
    result = hp.hp_build(_evidence(tmp_path), str(out), recipient, config_dir=str(tmp_path / "cfg"))
    assert result["encrypted"] and result["path"].endswith(".zip.age") and result["files"] == 3
    assert os.listdir(out) == [os.path.basename(result["path"])]          # no .part, no plaintext zip
    with open(result["path"], "rb") as fh:
        assert fh.read(21) == b"age-encryption.org/v1"
    zf = _open(result["path"], identity)
    names = set(zf.namelist())
    assert {"files/evidence/report.json", "files/evidence/screens/sms.png", "files/capture.pcap",
            "acquisition.json", "hashes.csv", "zero-breach/manifest.json", "zero-breach/manifest.sig",
            "zero-breach/sender-key.txt", "zero-breach/README.txt"} <= names
    from test_ageseal import _age_decrypt
    plain = tmp_path / "package.zip"
    with open(result["path"], "rb") as fh:
        plain.write_bytes(_age_decrypt(fh.read(), identity))
    check = hp.hp_verify(str(plain))
    assert check["ok"] and check["files"] == 3 and check["safety_number"] == result["safety_number"]


def test_wrong_key_cannot_open_it(tmp_path, helper):
    _identity, recipient = helper
    result = hp.hp_build(_evidence(tmp_path), str(tmp_path / "o"), recipient, config_dir=str(tmp_path / "c"))
    with pytest.raises(Exception):
        _open(result["path"], os.urandom(32))


def test_tampering_is_detected(tmp_path):
    result = hp.hp_build(_evidence(tmp_path), str(tmp_path / "o"), None, config_dir=str(tmp_path / "c"))
    src = zipfile.ZipFile(result["path"])
    changed = tmp_path / "changed.zip"
    with zipfile.ZipFile(changed, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            dst.writestr(name, b"swapped" if name == "files/capture.pcap" else data)
    check = hp.hp_verify(str(changed))
    assert not check["ok"] and check["signed"] and "capture.pcap" in check["problems"][0]
    forged = tmp_path / "forged.zip"
    with zipfile.ZipFile(forged, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == "zero-breach/manifest.json":
                data = data.replace(b'"files"', b'"files" ', 1)
            dst.writestr(name, data)
    assert not hp.hp_verify(str(forged))["signed"]


def test_androidqf_collection_is_kept_at_the_top_untouched(tmp_path, helper):
    identity, recipient = helper
    col = tmp_path / "b5c1e1aa-androidqf"
    (col / "apks").mkdir(parents=True)
    (col / "acquisition.json").write_text('{"UUID": "b5c1"}', encoding="utf-8")
    (col / "packages.json").write_text("[]", encoding="utf-8")
    (col / "hashes.csv").write_text("x", encoding="utf-8")
    (col / "apks" / "a.apk").write_bytes(b"PK")
    result = hp.hp_build([str(col)], str(tmp_path / "o"), recipient, config_dir=str(tmp_path / "c"))
    zf = _open(result["path"], identity)
    assert result["androidqf"]
    assert zf.read("acquisition.json") == b'{"UUID": "b5c1"}' and zf.read("hashes.csv") == b"x"
    assert "apks/a.apk" in zf.namelist() and not any(n.startswith("files/") for n in zf.namelist())


def test_no_user_or_computer_name_in_the_package(tmp_path):
    result = hp.hp_build(_evidence(tmp_path), str(tmp_path / "o"), None, config_dir=str(tmp_path / "c"))
    zf = zipfile.ZipFile(result["path"])
    text = b"".join(zf.read(n) for n in zf.namelist() if n.endswith((".json", ".csv", ".txt")))
    for private in {os.path.basename(os.path.expanduser("~")), socket.gethostname(), str(tmp_path)}:
        if len(private) > 2:
            assert private.encode() not in text


def test_the_sender_key_is_reused_and_never_packaged(tmp_path):
    cfg = tmp_path / "cfg"
    first = hp.hp_build(_evidence(tmp_path), str(tmp_path / "o1"), None, config_dir=str(cfg))
    again = hp.hp_build([str(cfg), str(tmp_path / "capture.pcap")], str(tmp_path / "o2"), None, config_dir=str(cfg))
    assert first["new_sender_key"] and not again["new_sender_key"]
    assert first["safety_number"] == again["safety_number"]
    names = zipfile.ZipFile(again["path"]).namelist()
    assert not any(n.endswith(hp.HP_KEY_NAME) for n in names)


def test_secret_key_and_typos_are_refused(tmp_path):
    with pytest.raises(ag.AgError, match="SECRET"):
        hp.hp_build(_evidence(tmp_path), str(tmp_path / "o"), "AGE-SECRET-KEY-1ABC", config_dir=str(tmp_path / "c"))
    assert not (tmp_path / "o").exists() or not os.listdir(tmp_path / "o")


def test_failure_leaves_no_partial_file(tmp_path, helper, monkeypatch):
    _identity, recipient = helper

    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(hp, "ed_sign", boom)
    with pytest.raises(RuntimeError):
        hp.hp_build(_evidence(tmp_path), str(tmp_path / "o"), recipient, config_dir=str(tmp_path / "c"))
    assert os.listdir(tmp_path / "o") == []


def test_still_encrypted_package_is_explained(tmp_path, helper):
    _identity, recipient = helper
    result = hp.hp_build(_evidence(tmp_path), str(tmp_path / "o"), recipient, config_dir=str(tmp_path / "c"))
    with pytest.raises(hp.HpError, match="still encrypted"):
        hp.hp_verify(result["path"])


def test_render_tells_what_to_read_aloud(tmp_path, helper):
    _identity, recipient = helper
    result = hp.hp_build(_evidence(tmp_path), str(tmp_path / "o"), recipient, config_dir=str(tmp_path / "c"))
    text = hp.hp_render(result)
    assert result["safety_number"] in text and result["package_code"] in text and "Nothing was uploaded" in text
    assert "NOT ENCRYPTED" in hp.hp_render(dict(result, encrypted=False, recipient=None))


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_makes_and_checks_a_package(bundle, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    monkeypatch.setattr(bundle, "hp_config_dir", lambda: str(tmp_path / "cfg"))
    paths = _evidence(tmp_path)
    out = tmp_path / "pkg"
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--package-for-helper", str(out),
                                "--add", paths[0], "--add", paths[1], "--no-encryption"]) == 0
    made = [f for f in os.listdir(out) if f.endswith(".zip")][0]
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--verify-package",
                                str(out / made)]) == 0
    assert "CHECK OUT" in capsys.readouterr().out


def test_cli_needs_something_to_add(tmp_path):
    from zbtriage import cli
    with pytest.raises(SystemExit):
        cli._parse(["--package-for-helper", str(tmp_path), "--no-encryption"])
