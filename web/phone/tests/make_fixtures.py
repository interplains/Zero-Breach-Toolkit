"""Synthetic iPhone backups for testing the browser phone check.

    python web/phone/tests/make_fixtures.py OUT_DIR [COUNT]

Writes, under OUT_DIR:
  plain-clean/        unencrypted backup, ordinary records only
  plain-hit/          unencrypted backup whose Safari history holds a built-in indicator
  encrypted-hit/      encrypted backup (password "fixture-pass"), same planted record,
                      with the key-derivation cost of a real iOS 10.2+ backup
                      (PBKDF2-SHA256 10,000,000 rounds, then PBKDF2-SHA1 10,000)
  parent/             a "Backup" folder holding two device backups (picker test)
  not-a-backup/       a folder of unrelated files
  android-clean/      AndroidQF-shaped collection (the engine's practice layout), no indicator
  android-hit/        the same with an installed app whose package name is a built-in indicator
  android-cellebrite/ the practice Cellebrite layout, found by the real Cellebrite check
  large-hit/          (only with a COUNT argument) a backup with COUNT extra payload files

The layout follows the format the engine's own tests document
(scan/tests/test_ios_upgrade.py). The planted value is taken from the shipped
indicator list at build time; it is only written into a test database and is
never contacted. Requires the cryptography package for the encrypted backup.
"""
import hashlib
import os
import plistlib
import shutil
import sqlite3
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
PASSWORD = b"fixture-pass"
REAL_DPIC, REAL_ITER = 10_000_000, 10_000


def planted_domain():
    sys.path.insert(0, os.path.join(REPO, "scan"))
    from zbtriage.iocs import load_any, TYPE_DOMAIN
    indicators = load_any(os.path.join(REPO, "iocs", "curated_mercenary.txt"))
    for ind in indicators.of_type(TYPE_DOMAIN):
        if ind.confidence == "primary":
            return ind.value
    raise SystemExit("no primary domain indicator found")


def sqlite_bytes(schema, rows):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "db.sqlite")
        con = sqlite3.connect(path)
        con.executescript(schema)
        for sql, params in rows:
            con.execute(sql, params)
        con.commit()
        con.close()
        with open(path, "rb") as fh:
            return fh.read()


def records(domain=None):
    urls = ["https://www.wikipedia.org/", "https://news.example.org/today"]
    if domain:
        urls.append("https://" + domain + "/a/b")
    safari = sqlite_bytes(
        "CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT);"
        "CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL,"
        " origin INTEGER NOT NULL DEFAULT 0, load_successful BOOLEAN NOT NULL DEFAULT 1);",
        [("INSERT INTO history_items(id,url) VALUES(?,?)", (n + 1, u)) for n, u in enumerate(urls)]
        + [("INSERT INTO history_visits(history_item,visit_time,origin) VALUES(?,?,0)", (n + 1, 780000000.0 + n))
           for n in range(len(urls))])
    sms = sqlite_bytes("CREATE TABLE message(ROWID INTEGER PRIMARY KEY, text TEXT, date INTEGER, is_from_me INTEGER);",
                       [("INSERT INTO message(text,date,is_from_me) VALUES(?,?,?)",
                         ("See you at 6", 780000000000000000, 0))])
    usage = sqlite_bytes("CREATE TABLE ZPROCESS(Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT, ZBUNDLENAME TEXT);",
                         [("INSERT INTO ZPROCESS(ZPROCNAME,ZBUNDLENAME) VALUES(?,?)",
                           ("MobileSafari", "com.apple.mobilesafari"))])
    return [("HomeDomain", "Library/Safari/History.db", safari),
            ("HomeDomain", "Library/SMS/sms.db", sms),
            ("WirelessDomain", "Library/Databases/DataUsage.sqlite", usage)]


def write_backup(root, items, name, encrypted=False, listed_only=0):
    os.makedirs(root)
    manifest = {"IsEncrypted": encrypted, "Version": "10.0"}
    class_key = hashlib.sha256(b"class-key").digest()
    if encrypted:
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        dpsl, salt = b"d" * 20, b"s" * 20
        secret = hashlib.pbkdf2_hmac("sha256", PASSWORD, dpsl, REAL_DPIC, 32)
        secret = hashlib.pbkdf2_hmac("sha1", secret, salt, REAL_ITER, 32)
        header = [(b"VERS", struct.pack(">I", 4)), (b"TYPE", struct.pack(">I", 1)), (b"UUID", b"h" * 16),
                  (b"DPSL", dpsl), (b"DPIC", struct.pack(">I", REAL_DPIC)),
                  (b"SALT", salt), (b"ITER", struct.pack(">I", REAL_ITER)),
                  (b"UUID", b"g" * 16), (b"CLAS", struct.pack(">I", 3)),
                  (b"WRAP", struct.pack(">I", 2)), (b"WPKY", aes_key_wrap(secret, class_key))]
        manifest["BackupKeyBag"] = b"".join(k + struct.pack(">I", len(v)) + v for k, v in header)
        manifest_key = hashlib.sha256(b"manifest-key").digest()
        manifest["ManifestKey"] = struct.pack("<I", 3) + aes_key_wrap(class_key, manifest_key)

    def enc(key, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        pad = 16 - len(data) % 16
        c = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
        return c.update(data + bytes([pad]) * pad) + c.finalize()

    db = os.path.join(root, "Manifest.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    for n, (domain, relative, raw) in enumerate(items):
        fid = hashlib.sha1((domain + "-" + relative).encode()).hexdigest()
        metadata, data = b"", raw
        if encrypted:
            from cryptography.hazmat.primitives.keywrap import aes_key_wrap
            key = hashlib.sha256(b"file-%d" % n).digest()
            obj = {"Size": len(raw), "ProtectionClass": 3,
                   "EncryptionKey": struct.pack("<I", 3) + aes_key_wrap(class_key, key)}
            metadata = plistlib.dumps({"$objects": ["$null", obj], "$top": {"root": plistlib.UID(1)}},
                                      fmt=plistlib.FMT_BINARY)
            data = enc(key, raw)
        os.makedirs(os.path.join(root, fid[:2]), exist_ok=True)
        with open(os.path.join(root, fid[:2], fid), "wb") as fh:
            fh.write(data)
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, domain, relative, 1, metadata))
    if listed_only:
        # Rows the checks never open (photos, app files), with metadata of a
        # realistic size, so Manifest.db reaches the size of a full phone's.
        filler = plistlib.dumps({"$objects": ["$null", {"Size": 123456, "ProtectionClass": 3,
                                                        "EncryptionKey": bytes(44), "Pad": bytes(160)}],
                                 "$top": {"root": plistlib.UID(1)}}, fmt=plistlib.FMT_BINARY)
        con.executemany("INSERT INTO Files VALUES(?,?,?,?,?)", (
            (hashlib.sha1(b"listed-%d" % n).hexdigest(), "CameraRollDomain",
             "Media/DCIM/1%02dAPPLE/IMG_%06d.HEIC" % (n % 100, n), 1, filler) for n in range(listed_only)))
    con.commit()
    con.close()
    if encrypted:
        with open(db, "rb") as fh:
            raw = fh.read()
        with open(db, "wb") as fh:
            fh.write(enc(manifest_key, raw))
    with open(os.path.join(root, "Manifest.plist"), "wb") as fh:
        fh.write(plistlib.dumps(manifest, fmt=plistlib.FMT_BINARY))
    with open(os.path.join(root, "Info.plist"), "wb") as fh:
        fh.write(plistlib.dumps({"Device Name": name, "Product Type": "iPhone15,2",
                                 "Product Version": "18.6", "Installed Applications": []}))
    with open(os.path.join(root, "Status.plist"), "wb") as fh:
        fh.write(plistlib.dumps({"IsFullBackup": False, "SnapshotState": "finished"}))


def write_large(root, count):
    """A backup shaped like a real phone's: tens of thousands of payload files
    in the 256 two-letter folders, listed in Manifest.db, plus the planted
    Safari record. Tests folder picking, mounting and the manifest inventory
    at realistic scale."""
    domain = planted_domain()
    write_backup(root, records(domain), "Large fixture phone")
    con = sqlite3.connect(os.path.join(root, "Manifest.db"))
    rows = []
    for n in range(count):
        relative = "Media/DCIM/100APPLE/IMG_%05d.HEIC" % n
        fid = hashlib.sha1(("CameraRollDomain-" + relative).encode()).hexdigest()
        folder = os.path.join(root, fid[:2])
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, fid), "wb") as fh:
            fh.write(bytes(64))
        rows.append((fid, "CameraRollDomain", relative, 1, b""))
    con.executemany("INSERT INTO Files VALUES(?,?,?,?,?)", rows)
    con.commit()
    con.close()


def write_android(root, scenario, app_id=None):
    """An AndroidQF-shaped collection, written by the engine's own practice
    builder (training._trn_collection), optionally with an installed app whose
    package name is a built-in indicator."""
    import json
    sys.path.insert(0, os.path.join(REPO, "scan"))
    from zbtriage.training import _trn_app, _trn_collection
    os.makedirs(root)
    _trn_collection(root, scenario)
    if app_id:
        path = os.path.join(root, "packages.json")
        with open(path, encoding="utf-8") as fh:
            packages = json.load(fh)
        packages.append(_trn_app(app_id, "com.android.packageinstaller", 10140, b"planted"))
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(packages, fh, indent=1)


def planted_app_id():
    sys.path.insert(0, os.path.join(REPO, "scan"))
    from zbtriage.iocs import load_any, TYPE_APP_ID
    for ind in load_any(os.path.join(REPO, "iocs", "curated_targeted.txt")).of_type(TYPE_APP_ID):
        if ind.confidence == "primary":
            return ind.value
    raise SystemExit("no primary app-id indicator found")


def main(out, large=0):
    out = os.path.abspath(out)
    if os.path.isdir(out):
        shutil.rmtree(out)
    domain = planted_domain()
    write_backup(os.path.join(out, "plain-clean"), records(), "Fixture phone (clean)")
    write_backup(os.path.join(out, "plain-hit"), records(domain), "Fixture phone (planted)")
    write_backup(os.path.join(out, "encrypted-hit"), records(domain), "Fixture phone (encrypted)", encrypted=True)
    write_backup(os.path.join(out, "parent", "00008110-000A1B2C3D4E5F60"), records(), "Old phone")
    write_backup(os.path.join(out, "parent", "00008120-0011223344556677"), records(domain), "New phone")
    os.makedirs(os.path.join(out, "not-a-backup"))
    with open(os.path.join(out, "not-a-backup", "notes.txt"), "w") as fh:
        fh.write("not a phone backup\n")
    write_android(os.path.join(out, "android-clean"), "clean")
    write_android(os.path.join(out, "android-hit"), "clean", planted_app_id())
    write_android(os.path.join(out, "android-cellebrite"), "cellebrite")
    if large:
        write_large(os.path.join(out, "large-hit"), large)
        write_backup(os.path.join(out, "huge-encrypted-hit"), records(domain), "Full phone (encrypted)",
                     encrypted=True, listed_only=300000)
    print("fixtures written to", out, "(planted indicator:", domain + ")")


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0)
