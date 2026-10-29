"""When cryptography is missing, the message names the Python running the check
and gives the command that installs it there (it is usually installed, but for
a different Python on the same computer)."""
import builtins
import sys

import pytest

from zbtriage import backupcrypto


def test_missing_cryptography_says_which_python_and_how_to_fix(monkeypatch):
    real_import = builtins.__import__

    def no_cryptography(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("no cryptography")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_cryptography)
    with pytest.raises(ValueError) as caught:
        backupcrypto.backup_ios_keys(b"", "password")
    text = str(caught.value)
    assert text.startswith("encrypted iPhone backups require optional cryptography")
    assert "Python {}.{}".format(sys.version_info[0], sys.version_info[1]) in text
    assert "python3 -m pip install --require-hashes -r requirements-backups.txt" in text
