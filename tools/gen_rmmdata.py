"""Generate scan/zbtriage/rmmdata.py: more remote-access and monitoring programs for the "Doors to close" check.

Source: LOLRMM (https://github.com/magicsword-io/LOLRMM), Apache License 2.0, its compiled
website/public/api/rmm_tools.json at a pinned commit. Usage:

    python tools/gen_rmmdata.py PATH_TO_rmm_tools.json COMMIT

LOLRMM is a list for security teams: it includes tools that only control OTHER computers (SSH and remote-desktop
clients), file-sync and backup services, VPNs and tunnels, security products, a screen reader, chat programs and
names that are ordinary words. Reporting any of those as "remote-access software is installed" would alarm people
for nothing. So nothing is taken automatically: INCLUDE below names each entry we use, with the kind we give it
and, where its name alone would match the wrong thing, the exact pattern. Everything not listed is left out on
purpose (the reasons are in EXCLUDED_BECAUSE, kept so a future update can be reviewed against them).

Program file names (for a remote-access program downloaded but never installed - the "download AnyDesk and read
me the code" scam) come from each included entry's PE metadata and installation paths, minus names too generic
to mean anything (agent.exe, client.exe, setup.exe ...).
"""
import fnmatch
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scan"))
OUT = os.path.join(HERE, "..", "scan", "zbtriage", "rmmdata.py")

R, M = "remote", "monitoring"

# LOLRMM Name -> (name shown, kind, pattern or None). None = built from the name: every word, word-bounded,
# spaces optional between words, case-insensitive.
INCLUDE = {
    "247ithelp.com (ConnectWise)": ("247ithelp (ConnectWise)", R, r"\b247ithelp\b"),
    "Addigy": ("Addigy agent", R, r"\baddigy\b"),
    "ITSupport247 (ConnectWise)": ("ITSupport247 (ConnectWise)", R, r"\bitsupport ?247\b"),
    "RG System (RG Supervision)": ("RG System agent", R, r"\brg (system|supervision)\b"),
    "Rodex RMM": ("Rodex RMM", R, r"\brodex\b"),
    "Access Remote PC": ("Access Remote PC", R, None),
    "Alpemix": ("Alpemix", R, None),
    "AnyViewer": ("AnyViewer", R, r"\banyviewer\b"),
    "Anyplace Control": ("Anyplace Control", R, None),
    "Aspia": ("Aspia", R, r"\baspia (host|router|relay)\b"),
    "AweRay": ("AweRay / AweSun", R, r"\baweray\b|\bawesun\b"),
    "BeAnyWhere": ("BeAnyWhere", R, None),
    "Beacon (Synertek)": ("Beacon (Synertek)", R, r"\bsynertek\b"),
    "BeamYourScreen": ("BeamYourScreen", R, None),
    "BlackCrypt RMM Agent": ("BlackCrypt RMM agent", R, r"\bblackcrypt\b"),
    "BreezeRMM": ("BreezeRMM", R, r"\bbreeze ?rmm\b"),
    "Bluetrait": ("Bluetrait agent", R, None),
    "CentraStage (Now Datto)": ("Datto RMM (CentraStage)", R, r"\bcentrastage\b|\bdatto rmm\b"),
    "Comodo RMM": ("Comodo / Itarian RMM", R, r"\bcomodo (rmm|one client)\b|\bitarian\b"),
    "Connectwise Automate (LabTech)": ("ConnectWise Automate (LabTech)", R,
                                       r"\blabtech\b|connectwise automate|\bltsvc\b"),
    "ControlR": ("ControlR", R, r"\bcontrolr\b"),
    "CrossLoop": ("CrossLoop", R, None),
    "CrossTec Remote Control": ("CrossTec Remote Control", R, r"\bcrosstec\b"),
    "CruzControl": ("CruzControl", R, None),
    "DeskDay": ("DeskDay", R, None),
    "Distant Desktop": ("Distant Desktop", R, None),
    "Echoware": ("Echoware", R, None),
    "Electric AI (Kaseya)": ("Electric AI", R, r"\belectric ai\b"),
    "Ericom AccessNow": ("Ericom AccessNow", R, r"\bericom\b"),
    "FastViewer": ("FastViewer", R, r"\bfastviewer\b"),
    "Faronics Insight": ("Faronics Insight", M, r"\bfaronics insight\b"),
    "FixMe.it": ("FixMe.it", R, r"\bfixme\.?it\b"),
    "FleetDeck.io": ("FleetDeck", R, r"\bfleetdeck\b"),
    "GatherPlace-desktop sharing": ("GatherPlace", R, r"\bgatherplace\b"),
    "GetScreen": ("Getscreen.me", R, r"\bgetscreen\b"),
    "GO RMM": ("GO RMM", R, r"\bgo ?rmm\b"),
    "Gorelo RMM": ("Gorelo RMM", R, r"\bgorelo\b"),
    "GoToMyPC": ("GoToMyPC", R, r"\bgotomypc\b"),
    "GotoHTTP": ("GotoHTTP", R, r"\bgotohttp\b"),
    "Goverlan": ("Goverlan", R, None),
    "GxM RMM Agent": ("GxM RMM agent", R, r"\bgxm rmm\b"),
    "HeartbeatRM": ("HeartbeatRM", R, r"\bheartbeatrm\b"),
    "HelpBeam": ("HelpBeam", R, None),
    "HelpWire": ("HelpWire", R, None),
    "HopToDesk": ("HopToDesk", R, r"\bhop ?to ?desk\b"),
    "I'm InTouch": ("I'm InTouch", R, r"\bi'?m ?intouch\b"),
    "ImmyBot": ("ImmyBot agent", R, r"\bimmy ?bot\b"),
    "Impero Connect": ("Impero Connect / Netop", R, r"\bimpero\b|\bnetop\b"),
    "Instant Housecall": ("Instant Housecall", R, None),
    "IntelliAdmin Remote Control": ("IntelliAdmin Remote Control", R, r"\bintelliadmin\b"),
    "Iperius Remote": ("Iperius Remote", R, None),
    "Ivanti Remote Control": ("Ivanti / LANDesk remote control", R, r"\bivanti remote control\b|\blandesk\b"),
    "Jump Cloud": ("JumpCloud agent", R, r"\bjump ?cloud\b"),
    "Kabuto": ("Kabuto", R, r"\bkabuto (agent|rmm)\b"),
    "KHelpDesk": ("KHelpDesk", R, None),
    "Laplink Everywhere": ("Laplink Everywhere", R, None),
    "Lavawall": ("Lavawall", R, None),
    "LightRmmAgent": ("LightRmm agent", R, r"\blight ?rmm\b"),
    "LS RMM": ("LS RMM", R, r"\bls ?rmm\b"),
    "Manage Engine (Desktop Central)": ("ManageEngine Endpoint Central (Desktop Central)", R,
                                        r"\bdesktop ?central\b|\bendpoint central\b|\bmanageengine (uems|rmm)\b"),
    "Mikogo": ("Mikogo", R, None),
    "Mini RMM Agent": ("Mini RMM agent", R, r"\bmini ?rmm\b"),
    "Miradore": ("Miradore", R, None),
    "MyGreenPC": ("MyGreenPC", R, r"\bmygreenpc\b"),
    "MyIVO": ("MyIVO", R, r"\bmyivo\b"),
    "Naverisk": ("Naverisk", R, None),
    "Net Monitor for Employees": ("Net Monitor for Employees", M, None),
    "NetLock RMM": ("NetLock RMM", R, r"\bnetlock rmm\b"),
    "NetSupport Manager": ("NetSupport Manager / School", R, r"\bnetsupport\b"),
    "Netviewer": ("Netviewer", R, r"\bnetviewer\b"),
    "Nexus RMM (Scogo)": ("Nexus RMM (Scogo)", R, r"\bscogo\b|\bnexus rmm\b"),
    "Nezha": ("Nezha monitoring agent", R, r"\bnezha[ -]?agent\b"),
    "NTR Remote": ("NTR Remote", R, r"\bntr ?remote\b|\bntrsupport\b"),
    "Obliance": ("Obliance", R, None),
    "OpenDesk RMM Agent": ("OpenDesk RMM agent", R, r"\bopendesk rmm\b"),
    "OpenUEM": ("OpenUEM agent", R, r"\bopenuem\b"),
    "OptiTune": ("OptiTune", R, None),
    "Pandora RC (eHorus)": ("Pandora RC (eHorus)", R, r"\bpandora rc\b|\behorus\b"),
    "Parallels Access": ("Parallels Access", R, None),
    "PChelpware": ("PChelpware", R, None),
    "Pcvisit": ("pcvisit", R, r"\bpcvisit\b"),
    "PDQ Connect": ("PDQ Connect agent", R, r"\bpdq connect\b"),
    "Ping32": ("Ping32", M, None),
    "Pocket Controller (Soti Xsight)": ("SOTI Pocket Controller / XSight", R, r"\bpocket ?controller\b|\bsoti\b"),
    "Pulseway": ("Pulseway", R, None),
    "Quest KACE Agent (formerly Dell KACE)": ("Quest / Dell KACE agent", R, r"\bkace (agent|amp)\b"),
    "RemoteCall": ("RemoteCall", R, r"\bremotecall\b"),
    "Remote Manipulator System": ("Remote Manipulator System (RMS)", R, r"\bremote manipulator\b"),
    "Remote.it": ("Remote.it", R, r"\bremote\.?it (desktop|agent|connectd)\b|\bremoteit\b"),
    "RemotePulse": ("RemotePulse", R, None),
    "RemSupp": ("RemSupp", R, None),
    "Remcos": ("Remcos", M, r"\bremcos\b"),
    "Remotely": ("Remotely agent", R, r"\bremotely agent\b"),
    "Rocket Remote Desktop": ("Rocket Remote Desktop", R, None),
    "RPort": ("RPort", R, r"\brport (client|agent)\b|\brportd?\b"),
    "RuDesktop": ("RuDesktop", R, r"\bru ?desktop\b"),
    "ScreenMeet": ("ScreenMeet", R, None),
    "Seetrol": ("Seetrol", R, None),
    "Senso.cloud": ("Senso.cloud", M, r"\bsenso\.?cloud\b"),
    "Sentinel RMM": ("Sentinel RMM", R, r"\bsentinel rmm\b"),
    "ServerEye": ("Server-Eye", R, r"\bserver-?eye\b"),
    "SetMe PRO": ("SetMe PRO", R, None),
    "SkyFex": ("SkyFex", R, None),
    "Sorillus": ("Sorillus", M, None),
    "SpyAnywhere": ("SpyAnywhere", M, None),
    "SunLogin": ("Sunlogin (Oray)", R, r"\bsun ?login\b|\boray\b"),
    "SuperOps": ("SuperOps agent", R, r"\bsuperops\b"),
    "Syncro": ("Syncro agent", R, r"\bsyncro (agent|live|msp)\b|\bsyncromsp\b"),
    "SysAid": ("SysAid agent", R, None),
    "Syspectr": ("Syspectr", R, None),
    "TeleDesktop": ("TeleDesktop", R, None),
    "TiFLUX": ("TiFLUX", R, None),
    "ToDesk": ("ToDesk", R, r"\btodesk\b"),
    "TurboMeeting": ("TurboMeeting", R, None),
    "UltraViewer": ("UltraViewer", R, r"\bultra ?viewer\b"),
    "UniSystem RMM": ("UniSystem RMM", R, r"\bunisystem rmm\b"),
    "Xeox": ("Xeox agent", R, None),
    "Zecurit": ("Zecurit agent", R, None),
    "baramundi Management Suite": ("baramundi Management Agent", R, r"\bbaramundi\b"),
    "eHorus": ("eHorus", R, r"\behorus\b"),
    "ezHelp": ("ezHelp", R, r"\bezhelp\b"),
    "WebEx (Remote Access)": ("Webex Remote Access", R, r"\bwebex remote access\b|\bwbxra\b"),
    "GoToAssist (GoTo Resolve)": ("GoTo Resolve / GoTo Assist", R, r"\bgoto (resolve|assist)\b|\bgotoassist\b"),
    # --- from LOLRMM's "RAT" category: only programs that let someone into THIS computer -------------------------
    "CHAOS RAT": ("CHAOS RAT", M, r"\bchaos rat\b"),
    "SparkRAT": ("SparkRAT", M, r"\bspark ?rat\b"),
    "Overlord": ("Overlord RAT", M, r"\boverlord rat\b"),
    "RMMCRAT": ("RMMCRAT", M, None),
    "Bitvise SSH Server": ("Bitvise SSH Server", R, r"\bbitvise ssh server\b|\bbvsshserver\b"),
    "Dataplicity": ("Dataplicity agent", R, None),
    "FreeNX": ("FreeNX server", R, r"\bfreenx\b"),
    "Guacamole": ("Apache Guacamole server", R, r"\bguacd\b|\bguacamole[- ]server\b"),
    "ShellHub": ("ShellHub agent", R, r"\bshellhub\b"),
    "SmartCode Web VNC": ("SmartCode Web VNC", R, r"\bsmartcode web ?vnc\b"),
    "TrustConnect": ("TrustConnect", R, None),
    "Veyon": ("Veyon (classroom monitoring)", M, r"\bveyon\b"),
    "X2Go": ("X2Go server", R, r"\bx2go ?server\b"),
    "XRDP": ("xrdp server", R, r"\bxrdp\b"),
    "Xpra": ("Xpra server", R, r"\bxpra server\b"),
    "pcAnywhere": ("pcAnywhere", R, r"\bpc ?anywhere\b"),
    "rdpwrap": ("RDP Wrapper (unofficial multi-user Remote Desktop)", R, r"\brdp ?wrap(per)?\b|\btermwrap\b"),
    "tmate": ("tmate", R, r"\btmate\b"),
    "WebRDP": ("WebRDP", R, r"\bwebrdp\b"),
}

EXCLUDED_BECAUSE = {
    "controls other computers only (client/viewer/console)": [
        "Apple Remote Desktop", "Bitvise SSH Client", "Chicken (of the VNC)", "Chrome SSH Extension",
        "Devolutions Remote Desktop Manager", "EMCO Remote Console", "ExtraPuTTY", "FreeRDP",
        "GoToAssist Agent Desktop Console", "JollysFastVNC", "Jump Desktop", "KiTTY", "MobaXterm", "Mocha VNC Lite",
        "Mremote", "PSEXEC", "PSEXEC (Clone)", "Pocket Cloud (Wyse)", "PuTTY", "PuTTY Tray", "RDCMan", "RDPView",
        "RdClient", "RdViewer", "Remmina", "Remote Desktop Manager (Devolutions)", "Remote Desktop Plus",
        "Royal Apps", "Royal Server", "Royal TS", "SecureCRT", "SmarTTY", "Solar-PuTTY", "SuperPuTTY",
        "Teleport Connect", "Terminals", "WinSCP", "Xshell", "ZOC", "mRemoteNG", "rdp2tcp", "Faronics Core",
        "mstsc.exe (Microsoft Remote Desktop Connection)", "Quick Assist"],
    "file sync, backup or sharing - not control": [
        "BeInSync", "DragonDisk", "Duplicati", "Insync", "Koofr", "MEGAsync", "MultCloud", "NordLocker",
        "Onionshare", "S3 Browser", "SmartFTP", "Syncthing", "Yandex.Disk", "iDrive", "MSP360",
        "Acronis Cyber Protect (Remotix)", "Laplink Gold", "MioNet (Also known as WD Anywhere Access)",
        "MioNet (WD Anywhere Access)", "Weezo", "Basecamp"],
    "VPN, tunnel or network tool (a separate question, not remote control)": [
        "CloudFlare Tunnel", "Dev Tunnels (aka Visual Studio Dev Tunnel)", "LocalXpose", "NetBird", "PiTunnel",
        "Tailscale", "ZeroTier", "ngrok", "Visual Studio Dev Tunnel", "VS Code Remote Tunnels", "Remobo",
        "Free Ping Tool", "ProxiPort"],
    "security, inventory or monitoring of servers - alarming and not a way in": [
        "Absolute (Computrace)", "Auvik", "Barracuda", "Domotz", "ESET Remote Administrator", "Faronics Deep Freeze",
        "GLPI Agent", "Netreo", "OCS inventory", "Panorama9", "Rapid7", "Site24x7", "Sophos-Remote Management System",
        "Tanium", "Tanium Deploy", "Vicarius vRx", "Zabbix Agent", "Freshservice", "InvGate",
        "ManageEngine ServiceDesk Plus", "StifleR (2Pint Software)", "Komari", "Monitic", "RES Automation Manager"],
    "software installers and launchers": [
        "Ninite Pro (Ninite Agent)", "Total Software Deployment", "Free Tools Launcher", "GoTo Opener",
        "Faronics Deploy"],
    "not remote access at all, or an everyday program": [
        "NVDA (Non-Visual Desktop Access)", "QQ IM-remote assistance", "AliWangWang-remote-control", "Adobe Connect",
        "Duet Display", "Synergy", "Mouse Without Borders", "DeskShare", "DeskNets", "Fortra",
        "NoteOn-desktop sharing"],
    "name is an ordinary word or too vague to match safely": [
        "Level", "Roster", "Centurion", "Borealis", "IT Agent", "Any Support", "Basic RMM Agent", "Endar", "Opale",
        "Encapto", "Allocentra", "Minexus", "Pilixo", "Neturo", "Remmon", "RemoteView", "Remote Ripple", "RemotePass",
        "Pcnow", "HelpU", "DesktopNow", "RunSmart", "VIZOR", "Lunixar", "OpsBridge Agent", "RMMmax", "Go Mini RMM",
        "NetMaster", "RemoteAgentAgent"],
    "already in our own list (accessdata.py), or under another entry above": [
        "Parsec", "Chrome Remote Desktop", "Atera", "BeyondTrust", "ConnectWise", "DW Service", "Ericom Connect",
        "Itarian", "LANDesk", "LabTeach (Connectwise Automate)", "LabTech RMM (Now ConnectWise Automate)",
        "Lite Manager", "ManageEngine", "ManageEngine RMM Central", "Netop", "Netop Remote Control (Impero Connect)",
        "Netop Remote Control (aka Impero Connect)", "Netviewer (GoToMeet)", "Pocket Controller", "RAdmin",
        "RealVNC", "RemoteUtilities", "Splashtop", "Splashtop (Beta)", "Splashtop Remote", "VNC"],
}

GENERIC_FILES = {
    "agent", "client", "setup", "install", "installer", "update", "updater", "service", "server", "remote",
    "launcher", "host", "helper", "support", "viewer", "uninstall", "unins000", "tray", "monitor", "app", "main",
    "run", "start", "console", "manager", "control", "connect", "desktop", "rc", "rs", "ra", "svc", "core",
    "winvnc", "vncviewer", "vncserver", "tvnserver", "screen", "chat", "sync", "msiexec",
}


def auto_pattern(name):
    words = re.findall(r"[A-Za-z0-9]+", re.sub(r"\(.*?\)", "", name))
    return r"\b" + r" ?".join(re.escape(w.lower()) for w in words) + r"\b"


# File names LOLRMM gives that would point at the wrong program, reviewed one by one.
FILE_EXCLUDE = {
    # names other everyday software uses
    "winpty-agent.exe", "winpty-agent64.exe",            # Git for Windows, VS Code terminals
    "hypersnap.exe",                                     # HyperSnap screenshot tool
    "iperius.exe",                                       # also Iperius Backup
    "intouch.exe",                                       # also the Wonderware InTouch control software
    "installcore.exe",                                   # an adware bundler of that name
    "laplink.exe",                                       # Laplink PCmover and others
    "tsclient.exe", "appcore.exe", "avcore.exe", "rcclient.exe", "rcservice.exe", "agentu.exe", "ilias.exe",
    "sysdiag.exe", "iadmin.exe", "supporttool.exe", "pcivideo.exe", "ddsystem.exe", "fastclient.exe",
    "serviceproxylocalsys.exe", "tiservice.exe", "tiupdateservice.exe", "otservice.exe", "hsloader.exe",
    "pstlaunch.exe", "pcstarter.exe", "screancap.exe", "studentsvc.exe", "stahelper.exe", "wysebrowser.exe",
    "sentinel-agent.exe", "beacon-agent.exe", "accessserver.exe", "accessserver*.exe", "echoserver*.exe",
    "agent-installer-any.exe", "agentsetup-*.exe", "agent_setup_5.exe", "ultimate_*.exe",
    "agent-windows-amd64-*.exe", "dashboard-windows-amd64.exe", "arcui.exe",
    "insightinstaller.exe", "insightinstallerstudent.exe", "insightinstallerteacher.exe",
    "ticlientcore.exe", "ticlienthelper*.exe",
    # GoTo Meeting's own files (g2m...) - a meeting app on many computers, not GoToMyPC
    "g2m_download.exe", "g2mchat.exe", "g2mcodecinstextractor.exe", "g2mcomm.exe", "g2mcoreinstextractor.exe",
    "g2mfeedback.exe", "g2minstaller.exe", "g2minstallerextractor.exe", "g2minsthigh.exe", "g2mlauncher.exe",
    "g2mmatchmaking.exe", "g2mmaterials.exe", "g2mpolling.exe", "g2mqanda.exe", "g2mrecorder.exe",
    "g2mscrutil64.exe", "g2msessioncontrol.exe", "g2mstart.exe", "g2mtesting.exe", "g2mtranscoder.exe",
    "g2muninstall.exe", "g2mupload.exe", "g2mvideoconference.exe", "g2mview.exe", "gotoscrutils.exe",
    "g2file*.exe", "g2quick.exe",
    # the technician's side: controls other computers, not a way into this one
    "rviewer.exe", "pchelpware_viewer.exe", "fixmeit expert setup.exe", "tiexpertcore.exe",
    "tiexpertstandalone.exe", "helpwire operator.app", "rdconsole.exe", "goverrmc.exe", "fastmaster.exe",
    "seetrolcenter.exe", "aspia_client.exe", "nxplayer.exe", "xpra-launcher.exe", "xpra-x86_64_setup.exe",
    "ezhelpmanager.exe", "ezhelpclientmanager.exe", "romviewer.exe", "rutview.exe", "tvnviewer.exe",
    "tightvncviewerportable*.exe",
    # programs our own list names, but under file names that are generic or belong to something else
    "goto opener.exe",                                   # GoTo Meeting's launcher
    "zohomeeting.exe", "zohotray.exe", "toolsiq.exe",    # Zoho Meeting / other Zoho apps
    "connectwise*.exe",                                  # would also match ConnectWise's ticketing app
    "update-shim.exe", "pservice.exe", "remote access.exe", "windowslauncher.exe", "vhost.exe", "spsrv.exe",
    "simpleservice.exe", "agentmon.exe", "agent_*_rw.exe", "agentmaint.exe", "agentmonitor.exe", "baseclient.exe",
    "wesvc.exe",
}

# Never allowed, whatever an upstream list says: names of Windows' own programs.
SYSTEM_FILES = {
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
    "rundll32.exe", "dllhost.exe", "conhost.exe", "taskhost.exe", "taskhostw.exe", "spoolsv.exe", "wininit.exe",
    "msiexec.exe", "cmd.exe", "powershell.exe", "mstsc.exe", "msra.exe", "quickassist.exe", "runtimebroker.exe",
}


def tool_files(tool):
    """Lowercase fnmatch patterns for the program's own file names."""
    names = set()
    pe = (tool.get("Details") or {}).get("PEMetadata")
    for item in (pe if isinstance(pe, list) else [pe] if isinstance(pe, dict) else []):
        for key in ("Filename", "OriginalFileName"):
            value = str((item or {}).get(key) or "").strip()
            if value:
                names.add(value)
    for path in (tool.get("Details") or {}).get("InstallationPaths") or []:
        base = re.split(r"[\\/]", str(path))[-1]
        if base.lower().endswith((".exe", ".app")):
            names.add(base)
    out = set()
    for raw in names:
        low = raw.lower().strip()
        if not low.endswith((".exe", ".app")) or "%" in low or "<" in low:
            continue
        stem = re.sub(r"\.(exe|app)$", "", low)
        core = re.sub(r"[*?\[\]_\-. 0-9]", "", stem)
        if len(core) < 5 or core in GENERIC_FILES or stem.strip("*") in GENERIC_FILES:
            continue
        if low in FILE_EXCLUDE or low in SYSTEM_FILES:
            continue
        if any(fnmatch.fnmatchcase(sysname, low) for sysname in SYSTEM_FILES):
            raise SystemExit("file pattern {!r} would match a Windows program - review it".format(low))
        out.add(low)
    return sorted(out)


def main(path, commit):
    from zbtriage.accessdata import OWN_ACCESS_PROGRAMS as OWN  # our hand-written list; it always wins
    own = [(n, re.compile(rx, re.I)) for n, _k, rx in OWN]
    own_kind = {n: k for n, k, _rx in OWN}
    data = json.load(open(path, encoding="utf-8"))
    by_name = {}
    for tool in data:
        by_name.setdefault(tool["Name"], tool)
    listed = set(INCLUDE) | {n for names in EXCLUDED_BECAUSE.values() for n in names}
    unreviewed = sorted(n for n in by_name if n not in listed and not any(rx.search(n) for _o, rx in own))
    missing = sorted(n for n in INCLUDE if n not in by_name)
    if missing:
        raise SystemExit("INCLUDE names not in this LOLRMM file: {}".format(missing))
    programs, files, seen = [], [], set()
    for lol_name in sorted(INCLUDE, key=str.lower):
        shown, kind, pattern = INCLUDE[lol_name]
        pattern = pattern or auto_pattern(lol_name)
        rx = re.compile(pattern, re.I)
        if any(orx.search(shown) or orx.search(lol_name) for _o, orx in own):
            continue                                    # our own list already has it
        if shown in seen:
            continue
        seen.add(shown)
        programs.append((shown, kind, pattern))
        for f in tool_files(by_name[lol_name]):
            files.append((shown, kind, f))
    # File names of the programs our own list already names (AnyDesk, TeamViewer ...), filed under our name:
    # the tools a scammer asks people to download are mostly these.
    covered = EXCLUDED_BECAUSE["already in our own list (accessdata.py), or under another entry above"]
    for lol_name, tool in sorted(by_name.items()):
        if lol_name in INCLUDE or (lol_name in listed and lol_name not in covered):
            continue
        hit = next((o for o, orx in own if orx.search(lol_name)), None)
        if hit:
            for f in tool_files(tool):
                files.append((hit, own_kind[hit], f))
    lines = ['"""More remote-access and monitoring programs, for the "Doors to close" check.', "",
             "Generated by tools/gen_rmmdata.py from LOLRMM (https://github.com/magicsword-io/LOLRMM), commit",
             commit + ", website/public/api/rmm_tools.json. LOLRMM: Apache License 2.0; see NOTICE and",
             "third_party/lolrmm/LICENSE. Hand-curated: only programs that let someone into this computer; the",
             "generator lists what was left out and why. Our own accessdata.py entries take precedence.", "",
             "RMM_PROGRAMS: (name shown, kind, pattern) - same shape as accessdata.ACCESS_PROGRAMS.",
             "RMM_FILES: (name shown, kind, lowercase file-name pattern) - the program's own files, to notice one",
             "that was downloaded but never installed.", '"""', "", "RMM_PROGRAMS = ("]
    lines += ["    ({!r}, {!r}, {!r}),".format(*p) for p in programs]
    lines += [")", "", "RMM_FILES = ("]
    lines += ["    ({!r}, {!r}, {!r}),".format(*f) for f in sorted(set(files), key=lambda x: (x[0].lower(), x[2]))]
    lines += [")", ""]
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("wrote {}: {} programs, {} file names".format(OUT, len(programs), len(set(files))))
    if unreviewed:
        print("NOT REVIEWED (new in this LOLRMM version - decide: INCLUDE or EXCLUDED_BECAUSE):")
        for n in unreviewed:
            print("   ", n)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
