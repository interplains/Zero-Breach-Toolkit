"""Live network connections of this computer, read-only and offline.

Lists the TCP connections that exist right now, with the program that owns each
one where the system says, and marks any whose remote address is an indicator.
Nothing is looked up or contacted: no reverse DNS, no whois, no ping. Domain
indicators cannot be matched this way (a connection carries only an address),
so the browser and cache checks remain the place for those.

Windows reads the system's own connection tables (iphlpapi), Linux reads
/proc/net, macOS asks the system lsof at its fixed path. Without administrator
rights some systems hide which program owns another account's connections;
those show as "unknown", never as clean.
"""
import ipaddress
import os
import socket
import struct
import subprocess
import sys

NC_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1",
    7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}
_NC_LINUX_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
    "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}
_NC_LSOF = "/usr/sbin/lsof"


def nc_is_remote(address):
    """True for an address on the internet, not this machine or a private network."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified
                or ip.is_multicast or ip.is_reserved)


def _nc_windows():
    import ctypes
    from ctypes import wintypes
    iphlp = ctypes.WinDLL("iphlpapi.dll")
    kernel = ctypes.WinDLL("kernel32.dll")
    names = {}

    def program(pid):
        if pid in names:
            return names[pid]
        name = ""
        if pid in (0, 4):
            name = "System" if pid == 4 else "System Idle"
        else:
            handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if handle:
                try:
                    buf = ctypes.create_unicode_buffer(1024)
                    size = wintypes.DWORD(len(buf))
                    if kernel.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                        name = buf.value
                finally:
                    kernel.CloseHandle(handle)
        names[pid] = name
        return name

    rows = []
    for family, row_size in ((socket.AF_INET, 24), (socket.AF_INET6, 56)):
        size = wintypes.DWORD(0)
        # TCP_TABLE_OWNER_PID_ALL = 5. First call asks for the size.
        iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, family, 5, 0)
        for _ in range(3):
            buf = ctypes.create_string_buffer(size.value + 4096)
            size = wintypes.DWORD(len(buf))
            if iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, family, 5, 0) == 0:
                break
        else:
            raise OSError("the system connection table could not be read")
        raw = buf.raw
        count = struct.unpack_from("<I", raw, 0)[0]
        for i in range(count):
            off = 4 + i * row_size
            if family == socket.AF_INET:
                state, laddr, lport, raddr, rport, pid = struct.unpack_from("<I4sI4sII", raw, off)
                local, remote = socket.inet_ntop(family, laddr), socket.inet_ntop(family, raddr)
            else:
                laddr, _lscope, lport, raddr, _rscope, rport, state, pid = struct.unpack_from(
                    "<16sII16sIIII", raw, off)
                local, remote = socket.inet_ntop(family, laddr), socket.inet_ntop(family, raddr)
            rows.append({"protocol": "TCP", "local": local, "local_port": socket.ntohs(lport & 0xFFFF),
                         "remote": remote, "remote_port": socket.ntohs(rport & 0xFFFF),
                         "state": NC_STATES.get(state, str(state)), "pid": pid, "program": program(pid)})
    return rows


def _nc_linux_hex_address(text):
    address, port = text.split(":")
    raw = bytes.fromhex(address)
    if len(raw) == 4:
        ip = socket.inet_ntop(socket.AF_INET, raw[::-1])
    else:
        ip = socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return ip, int(port, 16)


def _nc_linux_owners():
    """socket inode -> (pid, program) for processes this account may inspect."""
    owners = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return owners
    for pid in pids:
        fd_dir = os.path.join("/proc", pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        program = ""
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:["):
                if not program:
                    try:
                        program = os.readlink(os.path.join("/proc", pid, "exe"))
                    except OSError:
                        program = ""
                owners[target[8:-1]] = (int(pid), program)
    return owners


def _nc_linux(root="/proc/net"):
    owners = _nc_linux_owners()
    rows = []
    for name in ("tcp", "tcp6"):
        try:
            with open(os.path.join(root, name), encoding="ascii", errors="replace") as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            try:
                local, lport = _nc_linux_hex_address(fields[1])
                remote, rport = _nc_linux_hex_address(fields[2])
            except (ValueError, OSError):
                continue
            pid, program = owners.get(fields[9], (None, ""))
            rows.append({"protocol": "TCP", "local": local, "local_port": lport, "remote": remote,
                         "remote_port": rport, "state": _NC_LINUX_STATES.get(fields[3], fields[3]),
                         "pid": pid, "program": program})
    return rows


def _nc_lsof_split(endpoint):
    host, _, port = endpoint.rpartition(":")
    host = host.strip("[]")
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def _nc_macos():
    if not os.path.isfile(_NC_LSOF):
        raise OSError("the system lsof tool is not available")
    proc = subprocess.run([_NC_LSOF, "-nP", "-iTCP", "-FpcnT"], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20,
                          env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
    rows, pid, program, current = [], None, "", None
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            pid, program = int(value) if value.isdigit() else None, ""
        elif tag == "c":
            program = value
        elif tag == "n":
            local, _, remote = value.partition("->")
            lhost, lport = _nc_lsof_split(local)
            rhost, rport = _nc_lsof_split(remote) if remote else ("", 0)
            current = {"protocol": "TCP", "local": lhost, "local_port": lport, "remote": rhost,
                       "remote_port": rport, "state": "", "pid": pid, "program": program}
            rows.append(current)
        elif tag == "T" and current is not None and value.startswith("ST="):
            current["state"] = value[3:]
    return rows


def nc_list():
    """(rows, problem). Each row: protocol, local, local_port, remote, remote_port,
    state, pid, program. On failure rows is [] and problem says why."""
    try:
        if sys.platform == "win32":
            return _nc_windows(), ""
        if sys.platform == "darwin":
            return _nc_macos(), ""
        if os.path.isdir("/proc/net"):
            return _nc_linux(), ""
        return [], "listing connections is not supported on this system"
    except (OSError, ValueError, subprocess.SubprocessError, AttributeError) as exc:
        return [], "connections could not be listed: {}".format(exc)


def nc_match(rows, iocs):
    """Mark rows whose remote address is an IP indicator. Returns the marked rows."""
    by_ip = {}
    for ind in getattr(iocs, "indicators", []):
        if getattr(ind, "type", "") == "ip":
            by_ip[ind.value] = ind
    for row in rows:
        row["remote_public"] = nc_is_remote(row["remote"])
        ind = by_ip.get(row["remote"].split("%", 1)[0].lower())
        row["match"] = ind
    return [r for r in rows if r.get("match") is not None]
