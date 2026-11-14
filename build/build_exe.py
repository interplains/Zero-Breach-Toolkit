"""Build the double-click program for this platform.

Windows: dist/zero-breach-toolkit.exe. macOS and Linux: dist/zero-breach-toolkit
(a single executable that opens in a terminal). Each platform builds its own;
the release workflow (.github/workflows/programs.yml) builds all of them on
GitHub's machines from the tagged source.

Packages the single-file build (dist/zero-breach-toolkit.py, made by
build/bundle.py) with PyInstaller. Run with the pinned build environment:

    build\\.venv\\Scripts\\python.exe build\\build_exe.py

Choices, each for a reason:
  --onefile   one download, nothing to unpack by hand.
  --noupx     UPX-packed executables are a well-known cause of antivirus false
              alarms; a security tool must not look like packed malware.
  version     product name and version are stamped into the file so that every
              build of a version carries identical metadata.
The executable is NOT signed, here or anywhere. This project is anonymous and a
code-signing certificate requires a named legal identity, so expect SmartScreen
to warn and some antivirus products to object. PyInstaller output is also not
byte-reproducible, unlike the single-file Python build. Running from source
avoids both. See docs/VERIFYING.md.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SOURCE = os.path.join(ROOT, "dist", "zero-breach-toolkit.py")
WORK = os.path.join(HERE, "pyinstaller")
PRODUCT = "Zero Breach Toolkit"


def version():
    text = open(os.path.join(ROOT, "scan", "zbtriage", "__init__.py"), encoding="utf-8").read()
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


def version_file(ver):
    nums = [int(x) for x in re.findall(r"\d+", ver)[:4]]
    nums += [0] * (4 - len(nums))
    tup = "({}, {}, {}, {})".format(*nums)
    path = os.path.join(WORK, "version_info.txt")
    os.makedirs(WORK, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tup}, prodvers={tup}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Zero Breach'),
      StringStruct('FileDescription', '{product} - spyware indicator check'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'zero-breach-toolkit'),
      StringStruct('LegalCopyright', 'Apache License 2.0'),
      StringStruct('OriginalFilename', 'zero-breach-toolkit.exe'),
      StringStruct('ProductName', '{product}'),
      StringStruct('ProductVersion', '{ver}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""".format(tup=tup, ver=ver, product=PRODUCT))
    return path


def main():
    if not os.path.isfile(SOURCE):
        sys.exit("missing {} - run build/bundle.py first".format(SOURCE))
    ver = version()
    if sys.platform == "darwin":
        # A Mac app bundle (Zero Breach Toolkit.app) that opens the window when
        # double-clicked; the release workflow puts it in a .dmg. PyInstaller
        # builds .app bundles as a folder (one-file .app is deprecated).
        cmd = [sys.executable, "-m", "PyInstaller", "--onedir", "--windowed", "--noupx",
               "--clean", "--noconfirm", "--name", PRODUCT,
               "--osx-bundle-identifier", "io.github.interplains.zerobreach",
               "--distpath", os.path.join(ROOT, "dist"), "--workpath", WORK,
               "--specpath", WORK, SOURCE]
    else:
        cmd = [sys.executable, "-m", "PyInstaller", "--onefile", "--console", "--noupx",
               "--clean", "--noconfirm", "--name", "zero-breach-toolkit",
               "--distpath", os.path.join(ROOT, "dist"), "--workpath", WORK,
               "--specpath", WORK, SOURCE]
    if os.name == "nt":
        # Windows shows these details under the file's Properties.
        cmd[-1:-1] = ["--version-file", version_file(ver)]
    print("building version", ver)
    subprocess.run(cmd, check=True)
    if sys.platform == "darwin":
        mac_info_plist()
    exe = program_path()
    print("wrote {} ({:,} bytes)".format(exe, os.path.getsize(exe)))


def mac_info_plist():
    """Two Info.plist entries, then the bundle re-signed (ad hoc, as PyInstaller signed it) so the signature
    stays valid after the edit:
      - why the app uses Bluetooth: macOS stops an app the moment it uses Bluetooth without saying why, and the
        tracker check (--trackers) listens to it;
      - that it accepts any file dropped on its icon, for "Check a suspicious file" (the window receives the
        file through Tk's open-document event). Viewer role, lowest rank: it never becomes the default app."""
    import plistlib
    app = os.path.join(ROOT, "dist", PRODUCT + ".app")
    plist = os.path.join(app, "Contents", "Info.plist")
    with open(plist, "rb") as fh:
        info = plistlib.load(fh)
    info["NSBluetoothAlwaysUsageDescription"] = (
        "The Bluetooth tracker check listens for AirTags and other trackers near you. It only receives; "
        "nothing is sent.")
    info["CFBundleDocumentTypes"] = [{"CFBundleTypeName": "Any file", "CFBundleTypeRole": "Viewer",
                                      "LSHandlerRank": "None", "LSItemContentTypes": ["public.item"]}]
    with open(plist, "wb") as fh:
        plistlib.dump(info, fh)
    subprocess.run(["codesign", "--force", "--deep", "--sign", "-", app], check=True)
    subprocess.run(["codesign", "--verify", "--deep", "--strict", app], check=True)
    print("added the Bluetooth permission text and re-signed", app)


def program_path():
    """The runnable file this platform's build produces."""
    if sys.platform == "darwin":
        return os.path.join(ROOT, "dist", PRODUCT + ".app", "Contents", "MacOS", PRODUCT)
    return os.path.join(ROOT, "dist", "zero-breach-toolkit" + (".exe" if os.name == "nt" else ""))


if __name__ == "__main__":
    main()
