"""DNS logs from a router, Pi-hole, AdGuard Home or a DNS server (--dns-log PATH, repeatable).

One log covers every device in the home or office - phones, tablets, TVs - without
touching any of them. Each looked-up name (and each address in a logged answer) is
compared with the indicators, offline. Nothing is resolved or contacted.

Formats, recognised from the file itself:
  dnsmasq / Pi-hole text log   "query[A] name from 192.168.1.5", "reply name is 1.2.3.4",
                               "gravity blocked name is 0.0.0.0" (Pi-hole), "config name is NXDOMAIN"
  Pi-hole FTL database         pihole-FTL.db, table/view queries(timestamp, domain, client, status)
  AdGuard Home query log       querylog.json, one JSON object per line ("T", "QH", "IP", "Result")
  BIND query log               "client ... 192.168.1.5#53412 (name): query: name IN A"
  Unbound                      "info: 192.168.1.5 name. A IN"
  Windows DNS Server debug log "Rcv 192.168.1.5 ... Q [...] A (7)example(3)com(0)"
  Zeek dns.log                 tab-separated with a "#fields" header (ts, id.orig_h, query, answers)

A name looked up is "dns-record" evidence (the lookup happened; contact is unverified).
A lookup the filter BLOCKED is "attempted": something on the network tried, and was stopped.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time

from ..localpaths import local_temp_dir, open_evidence_db, path_problem
from ..result import EV_ATTEMPTED, EV_DNS, Hit, ModuleResult

NAME = "dns-logs"

_DL_MAX_BYTES = 4 * 1024 * 1024 * 1024    # per file, streamed
_DL_MAX_LINE = 64 * 1024
_DL_DEADLINE = 1800                         # seconds for all logs
_DL_DB_MAX = 2 * 1024 * 1024 * 1024
_DL_PIHOLE_BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18}
_DL_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep",
                                           "oct", "nov", "dec"), 1)}

_DL_DNSMASQ = re.compile(r"(?:dnsmasq|pihole-FTL)\[\d+\]: (query\[\w+\]|reply|cached|forwarded|"
                         r"(?:gravity |regex |exactly |special domain )?blocked|config|/etc/hosts) (\S+) "
                         r"(?:from|is|to) (\S+)")
_DL_SYSLOG_TIME = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
_DL_ISO_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
_DL_BIND = re.compile(r"client (?:@0x[0-9a-f]+ )?([0-9a-fA-F.:]+)#\d+ \(([^)]+)\): (?:view \S+: )?query: (\S+) IN (\w+)")
_DL_UNBOUND = re.compile(r"info: ([0-9a-fA-F.:]+) (\S+?)\.? (\w+) IN\b")
_DL_WINDNS = re.compile(r"\bRcv\s+([0-9a-fA-F.:]+)\s+\S+\s+Q\s+\[[^\]]*\]\s+(\w+)\s+((?:\(\d+\)[^\s(]*)+\(0\))")


def dl_windns_name(encoded):
    """'(7)example(3)com(0)' -> 'example.com'."""
    return ".".join(p for p in re.split(r"\(\d+\)", encoded) if p)


def dl_clean(name):
    name = (name or "").strip().strip(".").lower()
    if not name or len(name) > 253 or not re.fullmatch(r"[a-z0-9._*-]+", name):
        return None
    return name


class _DnsLogReader:
    def __init__(self, ctx, r):
        self.ctx, self.r = ctx, r
        self.queries = 0
        self.clients = set()
        # dnsmasq writes "query[A] name from CLIENT" and then, for a filtered name, "blocked name is
        # 0.0.0.0" without the client: remember the last client per name to say who tried.
        self.last_client = {}
        self.owners = {}                                  # which big company runs the names looked up
        self.first = self.last = None
        self.deadline = time.monotonic() + _DL_DEADLINE

    # --- matching ---------------------------------------------------------------
    def match(self, name, client, when, where, blocked, answer=None):
        iocs = self.ctx.iocs
        if client:
            self.clients.add(client)
        from ..ncinfo import nc_name_owner
        owner = nc_name_owner(name)
        if owner:
            self.owners[owner] = self.owners.get(owner, 0) + 1
        if when:
            self.first = when if self.first is None or when < self.first else self.first
            self.last = when if self.last is None or when > self.last else self.last
        grade = EV_ATTEMPTED if blocked else EV_DNS
        who = " by {}".format(client) if client else ""
        name = dl_clean(name)
        if name:
            self.queries += 1
            ind = iocs.lookup_typed("ip", name)
            labels = name.split(".")
            for n in range(len(labels) - 1):
                if ind is None:
                    ind = iocs.lookup_typed("domain", ".".join(labels[n:]))
            if ind is not None:
                detail = ("{} looked up{} in the DNS log; ".format(name, who) +
                          ("the filter blocked it (an attempt, stopped)" if blocked
                           else "endpoint contact is unverified"))
                self._hit(ind, where, detail, grade, when)
        if answer:
            try:
                ipaddress.ip_address(answer)
            except ValueError:
                return
            ind = iocs.lookup_typed("ip", answer)
            if ind is not None:
                self._hit(ind, where, "address {} returned{} in the DNS log; endpoint contact is unverified".format(
                    answer, who), EV_DNS, when)

    def _hit(self, ind, where, detail, grade, when):
        self.r.add_hit(Hit(ind.value, where, detail, ind.tier, ind.confidence, ind.source, grade,
                           when or "", family=ind.family, kind=ind.type))

    # --- formats ------------------------------------------------------------------
    def sniff(self, path):
        with open(path, "rb") as fh:
            head = fh.read(4096)
        if head.startswith(b"SQLite format 3\x00"):
            return "pihole-db"
        text = head.decode("utf-8", "replace")
        if text.lstrip().startswith("{") and '"QH"' in text:
            return "adguard"
        if text.startswith("#separator") or "\n#fields\t" in text or text.startswith("#fields\t"):
            return "zeek"
        return "text"

    def read(self, path, label):
        kind = self.sniff(path)
        if kind == "pihole-db":
            return kind, self._pihole_db(path, label)
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            if kind == "adguard":
                return kind, self._lines(fh, label, self._adguard)
            if kind == "zeek":
                return kind, self._zeek(fh, label)
            return kind, self._lines(fh, label, self._text)

    def _lines(self, fh, label, parse):
        matched, size, long_lines = 0, 0, 0
        year = datetime.date.today().year
        for n, line in enumerate(fh, 1):
            size += len(line)
            if size > _DL_MAX_BYTES:
                self.r.could_not_run("dns-log:" + label, "the log is larger than the {:,} MB this check "
                                     "reads; the rest was not checked".format(_DL_MAX_BYTES // 2 ** 20))
                return matched
            if n % 50000 == 0 and time.monotonic() > self.deadline:
                self.r.could_not_run("dns-log:" + label, "time limit reached at line {:,}; the rest was not "
                                     "checked".format(n))
                return matched
            if len(line) > _DL_MAX_LINE:
                long_lines += 1
                continue
            matched += parse(line, "{}, line {}".format(label, n), year)
        if long_lines:
            self.r.note("{}: {:,} line(s) longer than {:,} KB were not read (no DNS log writes lines that long; "
                        "they are usually damage or a different file).".format(label, long_lines,
                                                                               _DL_MAX_LINE // 1024))
        return matched

    def _when(self, line, year):
        m = _DL_ISO_TIME.match(line)
        if m:
            return m.group(1) + " " + m.group(2)
        m = _DL_SYSLOG_TIME.match(line)
        if m and m.group(1).lower() in _DL_MONTHS:
            return "{:04d}-{:02d}-{:02d} {}:{}:{}".format(year, _DL_MONTHS[m.group(1).lower()], int(m.group(2)),
                                                         m.group(3), m.group(4), m.group(5))
        return None

    def _text(self, line, where, year):
        m = _DL_DNSMASQ.search(line)
        if m:
            action, name, other = m.groups()
            when = self._when(line, year)
            if action.startswith("query"):
                if len(self.last_client) > 100000:
                    self.last_client.clear()
                self.last_client[name.lower()] = other
                self.match(name, other, when, where, blocked=False)
            elif "blocked" in action:
                self.match(name, self.last_client.get(name.lower()), when, where, blocked=True)
            elif action in ("reply", "cached"):
                self.match(None, None, when, where, blocked=False, answer=other)
            return 1
        m = _DL_BIND.search(line)
        if m:
            self.match(m.group(3), m.group(1), self._when(line, year), where, blocked=False)
            return 1
        m = _DL_WINDNS.search(line)
        if m:
            self.match(dl_windns_name(m.group(3)), m.group(1), self._when(line, year), where, blocked=False)
            return 1
        m = _DL_UNBOUND.search(line)
        if m:
            self.match(m.group(2), m.group(1), self._when(line, year), where, blocked=False)
            return 1
        return 0

    def _adguard(self, line, where, _year):
        try:
            row = json.loads(line)
        except ValueError:
            return 0
        if not isinstance(row, dict) or "QH" not in row:
            return 0
        result = row.get("Result") or {}
        blocked = bool(isinstance(result, dict) and result.get("IsFiltered"))
        when = str(row.get("T", ""))[:19].replace("T", " ") or None
        self.match(str(row.get("QH")), str(row.get("IP") or "") or None, when, where, blocked)
        return 1

    def _zeek(self, fh, label):
        fields, matched = None, 0
        for n, line in enumerate(fh, 1):
            if line.startswith("#fields"):
                fields = line.rstrip("\r\n").split("\t")[1:]
                continue
            if line.startswith("#") or not fields:
                continue
            values = dict(zip(fields, line.rstrip("\r\n").split("\t")))
            when = None
            try:
                when = datetime.datetime.fromtimestamp(float(values.get("ts", "")), datetime.timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S")
            except (ValueError, OverflowError, OSError):
                pass
            where = "{}, line {}".format(label, n)
            client = values.get("id.orig_h") or None
            self.match(values.get("query"), client, when, where, blocked=False)
            for answer in (values.get("answers") or "").split(","):
                if answer and answer != "-":
                    self.match(None, client, when, where, blocked=False, answer=answer)
            matched += 1
            if n % 50000 == 0 and time.monotonic() > self.deadline:
                self.r.could_not_run("dns-log:" + label, "time limit reached; the rest was not checked")
                break
        return matched

    def _pihole_db(self, path, label):
        if os.path.getsize(path) > _DL_DB_MAX:
            raise ValueError("the database is larger than the {:,} MB this check copies".format(_DL_DB_MAX // 2 ** 20))
        tmp = tempfile.mkdtemp(prefix="zbt_dns_", dir=local_temp_dir())
        try:
            copy = os.path.join(tmp, "ftl.db")
            shutil.copyfile(path, copy)
            for side in ("-wal", "-shm"):
                if os.path.isfile(path + side):
                    shutil.copyfile(path + side, copy + side)
            con = open_evidence_db(copy)
            try:
                matched = 0
                for n, (stamp, domain, client, status) in enumerate(con.execute(
                        "SELECT timestamp, domain, client, status FROM queries")):
                    when = None
                    try:
                        when = datetime.datetime.fromtimestamp(int(stamp), datetime.timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S")
                    except (TypeError, ValueError, OverflowError, OSError):
                        pass
                    self.match(str(domain or ""), str(client or "") or None, when,
                               "{}, query {}".format(label, n + 1), blocked=status in _DL_PIHOLE_BLOCKED)
                    matched += 1
                    if n % 50000 == 0 and time.monotonic() > self.deadline:
                        self.r.could_not_run("dns-log:" + label, "time limit reached; the rest was not checked")
                        break
                return matched
            finally:
                con.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    reader = _DnsLogReader(ctx, r)
    r.note("DNS logs: every name looked up is compared with the indicators offline; nothing is resolved or "
           "contacted.")
    for path in getattr(ctx, "dns_logs", ()) or ():
        label = os.path.basename(path)
        problem = path_problem(os.path.abspath(path))
        if problem:
            r.could_not_run("dns-log:" + label, "refused: " + problem)
            continue
        try:
            kind, entries = reader.read(path, label)
        except (OSError, ValueError, sqlite3.Error, UnicodeError) as exc:
            r.could_not_run("dns-log:" + label, "the log could not be read: {}".format(str(exc)[:200]))
            continue
        if not entries:
            r.could_not_run("dns-log:" + label, "no DNS records in a supported format were found in this file "
                            "(dnsmasq/Pi-hole, Pi-hole database, AdGuard Home, BIND, Unbound, Windows DNS "
                            "Server debug log or Zeek)")
            continue
        if not any(c.name == "dns-log:" + label and not c.ran for c in r.checks):
            r.ran("dns-log:" + label)
        r.note("{}: {} format, {:,} records.".format(label, kind, entries))
    r.checked = reader.queries
    r.submetrics["dns_log_queries"] = reader.queries
    r.submetrics["dns_log_clients"] = len(reader.clients)
    if reader.first:
        r.reach["dns-logs"] = {"earliest": reader.first, "days": None,
                               "basis": "the oldest record in the DNS logs given",
                               "note": "Only the period the logs cover was checked (latest {}).".format(reader.last)}
    r.note("Names looked up: {:,}, from {} devices.".format(reader.queries, len(reader.clients)))
    if reader.owners:
        top = sorted(reader.owners.items(), key=lambda kv: -kv[1])[:6]
        r.note("Most looked-up companies: " + ", ".join("{} ({:,})".format(o, n) for o, n in top) + ".")
    return r
