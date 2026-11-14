"""Strictly offline Authenticode check on Windows: is a program signed by a publisher Windows trusts?

Uses Windows' own verifier (WinVerifyTrust) with revocation checking switched off and cache-only URL retrieval,
so it never contacts the network (the reason the general signature step stays off elsewhere). Checks the
signature embedded in the file and, when there is none, Windows' signed catalogues - which is how most built-in
system files are signed. Returns a short status; never raises.

  signed         a valid signature from a publisher Windows trusts (embedded or catalogue)
  not-signed     no signature at all
  bad-signature  a signature that does not match the file, or one from a root Windows does not trust
  expired-signature  signed, but the certificate has expired and the signature had no timestamp (common, harmless)
  missing        the file does not exist
  unknown        the check could not run (not Windows, access denied, ...)
"""
from __future__ import annotations

import ctypes
import os
import sys

WS_SIGNED, WS_UNSIGNED, WS_BAD, WS_MISSING, WS_UNKNOWN = "signed", "not-signed", "bad-signature", "missing", "unknown"
WS_EXPIRED = "expired-signature"

_WS_NO_SIGNATURE = {0x800B0100, 0x800B0003, 0x800B0001}          # TRUST_E_NOSIGNATURE, SUBJECT_FORM_UNKNOWN, PROVIDER
_WS_BAD = {0x80096010, 0x800B0109, 0x800B010C, 0x80096019, 0x800B0111}   # bad digest, untrusted root, revoked, ...
_WS_EXPIRED = 0x800B0101                                                  # signed, certificate since expired


if sys.platform == "win32":
    from ctypes import wintypes

    class _WsGuid(ctypes.Structure):
        _fields_ = [("d1", wintypes.DWORD), ("d2", wintypes.WORD), ("d3", wintypes.WORD), ("d4", ctypes.c_ubyte * 8)]

    class _WsFileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class _WsCatalogInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]

    class _WsData(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD), ("pSignatureSettings", ctypes.c_void_p)]

    class _WsCatInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]

    _WS_ACTION = _WsGuid(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    _WS_UI_NONE, _WS_REVOKE_NONE, _WS_CHOICE_FILE, _WS_CHOICE_CATALOG = 2, 0, 1, 2
    _WS_STATE_VERIFY, _WS_STATE_CLOSE = 1, 2
    _WS_FLAGS = 0x1000 | 0x10           # WTD_CACHE_ONLY_URL_RETRIEVAL (never fetch) | WTD_REVOCATION_CHECK_NONE


def _ws_verify(choice, info):
    wintrust = ctypes.WinDLL("wintrust")
    data = _WsData()
    data.cbStruct = ctypes.sizeof(_WsData)
    data.dwUIChoice = _WS_UI_NONE
    data.fdwRevocationChecks = _WS_REVOKE_NONE
    data.dwUnionChoice = choice
    data.pInfo = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
    data.dwStateAction = _WS_STATE_VERIFY
    data.dwProvFlags = _WS_FLAGS
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(_WsGuid), ctypes.c_void_p]
    result = wintrust.WinVerifyTrust(None, ctypes.byref(_WS_ACTION), ctypes.byref(data))
    data.dwStateAction = _WS_STATE_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(_WS_ACTION), ctypes.byref(data))
    return result & 0xFFFFFFFF


def _ws_catalog(path):
    """Status from Windows' signed catalogues, or None if the file is in no catalogue."""
    wintrust = ctypes.WinDLL("wintrust")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    handle = kernel.CreateFileW(path, 0x80000000, 0x1 | 0x2 | 0x4, None, 3, 0, None)   # read, share all, existing
    if handle in (None, wintypes.HANDLE(-1).value):
        return None
    admin = wintypes.HANDLE()
    try:
        acquired = False
        try:
            wintrust.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
                                                             wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
            acquired = bool(wintrust.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, "SHA256", None, 0))
        except AttributeError:
            pass
        if not acquired:
            wintrust.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
                                                            wintypes.DWORD]
            if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(admin), None, 0):
                return None
        size = wintypes.DWORD(64)
        digest = (ctypes.c_ubyte * 64)()
        try:
            calc = wintrust.CryptCATAdminCalcHashFromFileHandle2
            calc.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                             wintypes.DWORD]
            ok = calc(admin, handle, ctypes.byref(size), digest, 0)
        except AttributeError:
            calc = wintrust.CryptCATAdminCalcHashFromFileHandle
            calc.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
            ok = calc(handle, ctypes.byref(size), digest, 0)
        if not ok:
            return None
        enum = wintrust.CryptCATAdminEnumCatalogFromHash
        enum.restype = wintypes.HANDLE
        enum.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        cat = enum(admin, digest, size.value, 0, None)
        if not cat:
            return None
        try:
            info = _WsCatInfo()
            info.cbStruct = ctypes.sizeof(_WsCatInfo)
            wintrust.CryptCATCatalogInfoFromContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            if not wintrust.CryptCATCatalogInfoFromContext(cat, ctypes.byref(info), 0):
                return None
            tag = "".join("{:02X}".format(b) for b in digest[:size.value])
            ci = _WsCatalogInfo()
            ci.cbStruct = ctypes.sizeof(_WsCatalogInfo)
            ci.pcwszCatalogFilePath = info.wszCatalogFile
            ci.pcwszMemberTag = tag
            ci.pcwszMemberFilePath = path
            ci.hMemberFile = handle
            ci.pbCalculatedFileHash = ctypes.cast(digest, ctypes.c_void_p)
            ci.cbCalculatedFileHash = size.value
            ci.hCatAdmin = admin
            return _ws_verify(_WS_CHOICE_CATALOG, ci)
        finally:
            wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
            wintrust.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
    finally:
        if admin.value:
            wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            wintrust.CryptCATAdminReleaseContext(admin, 0)
        kernel.CloseHandle(handle)


def ws_status(path: str) -> str:
    """Offline signature status of one file (see the module docstring)."""
    if sys.platform != "win32":
        return WS_UNKNOWN
    try:
        if not path or not os.path.isfile(path):
            return WS_MISSING
        info = _WsFileInfo()
        info.cbStruct = ctypes.sizeof(_WsFileInfo)
        info.pcwszFilePath = path
        code = _ws_verify(_WS_CHOICE_FILE, info)
        if code == 0:
            return WS_SIGNED
        if code in _WS_NO_SIGNATURE:
            cat = _ws_catalog(path)
            if cat == 0:
                return WS_SIGNED
            if cat is not None and cat in _WS_BAD:
                return WS_BAD
            if cat == _WS_EXPIRED:
                return WS_EXPIRED
            return WS_UNSIGNED
        if code == _WS_EXPIRED:
            return WS_EXPIRED
        if code in _WS_BAD:
            return WS_BAD
        return WS_UNKNOWN
    except (OSError, AttributeError, ValueError):
        return WS_UNKNOWN
