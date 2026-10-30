"""When HTTPS certificates cannot be checked, the help fits the system it runs
on (a Windows user was told about the Mac fix and a Linux package), and a
collector that never downloaded leaves nothing behind and says nothing was
collected from the phone."""
import contextlib
import io
import ssl
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

from zbtriage import feeds, phoneguide


def test_help_fits_each_system():
    windows = feeds._certificate_help(platform="win32")
    assert "Invoke-WebRequest https://github.com" in windows and "antivirus" in windows
    assert "ca-certificates" not in windows and "Install Certificates" not in windows
    assert "Install Certificates.command" in feeds._certificate_help(platform="darwin")
    assert "ca-certificates" in feeds._certificate_help(platform="linux")
    assert feeds._certificate_help().startswith("this Python cannot check website certificates, so nothing was downloaded")


def test_failed_collector_download_explains_and_leaves_nothing(tmp_path):
    def download(asset, digest, path):
        raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"))

    err = io.StringIO()
    with patch.object(phoneguide, "_phone_download", download), \
         patch.object(phoneguide.platform, "machine", return_value="amd64"), \
         patch.object(phoneguide.sys.stdin, "isatty", return_value=True), \
         patch("builtins.input", return_value="YES"), \
         contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        folder, code = phoneguide.collect_android(str(tmp_path / "collected"))
    text = err.getvalue()
    assert folder is None and code == 1
    assert "cannot check website certificates, so the collector was not downloaded and nothing was collected" in text
    assert "Nothing was collected from the phone." in text
    assert "private records" not in text
    assert not any(p.name.startswith("androidqf_") for p in Path(tmp_path / "collected").iterdir())


import os
import pytest


@pytest.mark.skipif(os.name != "nt", reason="the notice is shown on Windows")
def test_unsigned_collector_notice_does_not_read_as_an_error(tmp_path):
    out = io.StringIO()
    with patch.object(phoneguide.sys.stdin, "isatty", return_value=True), \
         patch.object(phoneguide.platform, "machine", return_value="amd64"), \
         patch("builtins.input", return_value="no"), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        phoneguide.collect_android(str(tmp_path / "collected"))
    text = out.getvalue()
    assert "This is a notice, not an error." in text
    assert "The Windows collector is unsigned" not in text
