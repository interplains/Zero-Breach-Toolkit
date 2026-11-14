"""Remote-access and computer-monitoring programs, for the "Doors to close" check.

Our own list (no third-party list is copied), compiled from the products' own names as published by their
makers. A match is NOT a finding: remote-access tools are used every day by IT support and families, and
monitoring products are sold to employers and parents. The point is that a person should know each one
that is on their computer and agree to it - the same programs are how a partner or ex keeps watch.

Each entry: (name shown to the person, kind, regular expression matched against installed program names,
service names, app bundle names and Linux desktop/unit names, case-insensitive).
kind "monitoring" = built to record what a person does (screens, keys, sites, messages): high severity.
kind "remote"     = lets someone see and control the computer from elsewhere: medium severity.

ACCESS_PROGRAMS (used by every check) = this list, then the hand-curated additions in rmmdata.py; where both name
a program, this list's entry is the one used.
"""

from .rmmdata import RMM_FILES, RMM_PROGRAMS

OWN_ACCESS_PROGRAMS = (
    # --- remote access ------------------------------------------------------------------------------
    ("TeamViewer", "remote", r"\bteam ?viewer\b"),
    ("AnyDesk", "remote", r"\bany ?desk\b"),
    ("RustDesk", "remote", r"\brust ?desk\b"),
    ("Chrome Remote Desktop", "remote", r"chrome remote desktop|\bchromoting\b|remoting_host"),
    ("Splashtop", "remote", r"\bsplashtop (streamer|remote service|business access agent)\b"),
    # Not GoTo Meeting / GoTo Opener / Hamachi (a VPN), which live under the LogMeIn name too.
    ("LogMeIn", "remote", r"^(?!.*(gotomeeting|goto meeting|gotoopener|goto opener|gotowebinar|g2m|hamachi))"
                          r".*\blogmein\b"),
    # Not "GoTo Opener": that is the launcher every GoTo Meeting user has, not remote access.
    ("GoTo Resolve / GoTo Assist", "remote", r"\bgoto (resolve|assist)\b|\bgotoassist\b"),
    ("ConnectWise ScreenConnect / Control", "remote", r"\bscreenconnect\b|connectwise control"),
    ("RemotePC", "remote", r"\bremotepc\b"),
    ("Zoho Assist", "remote", r"\bzoho assist\b|\bzohoassist\b"),
    ("UltraVNC", "remote", r"\bultra ?vnc\b"),
    ("TightVNC", "remote", r"\btight ?vnc\b"),
    ("RealVNC / VNC Server", "remote", r"\breal ?vnc server\b|\bvnc server\b|\bvncserver\b|\bvnc connect\b"),
    ("TigerVNC", "remote", r"\btiger ?vnc\b"),
    ("Remote Utilities", "remote", r"\bremote utilities\b"),
    ("Ammyy Admin", "remote", r"\bammyy\b"),
    ("Radmin Server", "remote", r"\bradmin server\b|\brserver3\b"),
    ("NoMachine", "remote", r"\bnomachine\b|\bnxserver\b"),
    ("Parsec", "remote", r"\bparsec\b"),
    ("AeroAdmin", "remote", r"\baeroadmin\b"),
    ("Supremo", "remote", r"\bsupremo\b"),
    ("DWService", "remote", r"\bdwservice\b|\bdwagent\b"),
    ("MeshCentral agent", "remote", r"\bmesh ?agent\b|\bmeshcentral\b"),
    ("Atera agent", "remote", r"\batera ?agent\b|\batera networks\b"),
    ("NinjaOne / NinjaRMM agent", "remote", r"\bninja ?rmm\b|\bninjaone\b"),
    ("Action1 agent", "remote", r"\baction1\b"),
    ("Tactical RMM agent", "remote", r"\btactical ?rmm\b"),
    ("SimpleHelp", "remote", r"\bsimple ?help\b"),
    ("ISL Online / ISL Light", "remote", r"\bisl (online|light|alwayson)\b"),
    ("BeyondTrust / Bomgar remote support", "remote", r"\bbomgar\b|beyondtrust remote support"),
    ("Kaseya VSA agent", "remote", r"\bkaseya\b"),
    ("N-able / SolarWinds Take Control", "remote", r"\btake control agent\b|\bn-able\b"),
    ("Dameware", "remote", r"\bdameware\b"),
    ("ShowMyPC", "remote", r"\bshowmypc\b"),
    ("LiteManager", "remote", r"\blitemanager\b"),
    # --- monitoring (records what the person does) ----------------------------------------------------
    ("Spyrix", "monitoring", r"\bspyrix\b"),
    ("Refog", "monitoring", r"\brefog\b"),
    ("KidLogger", "monitoring", r"\bkid ?logger\b"),
    ("Teramind", "monitoring", r"\bteramind\b"),
    ("ActivTrak", "monitoring", r"\bactivtrak\b"),
    ("Veriato / Spector", "monitoring", r"\bveriato\b|\bspector (360|pro|cns)\b"),
    ("InterGuard", "monitoring", r"\binterguard\b"),
    ("SpyAgent (Spytech)", "monitoring", r"\bspy ?agent\b|\bspytech\b"),
    ("Realtime-Spy", "monitoring", r"\brealtime-?spy\b"),
    ("Ardamax Keylogger", "monitoring", r"\bardamax\b"),
    ("Revealer Keylogger", "monitoring", r"\brevealer keylogger\b"),
    ("Elite Keylogger", "monitoring", r"\belite keylogger\b"),
    ("Actual Keylogger / Actual Spy", "monitoring", r"\bactual (keylogger|spy)\b"),
    ("Best Free Keylogger", "monitoring", r"\bbest free keylogger\b"),
    # Not anti-keyloggers (SpyShelter Anti-Keylogger, Zemana AntiLogger...): they protect against keyloggers.
    ("Any keylogger (name contains 'keylogger')", "monitoring", r"(?<!anti)(?<!anti-)(?<!anti )keylogger"),
    ("SentryPC", "monitoring", r"\bsentrypc\b"),
    ("Wolfeye", "monitoring", r"\bwolfeye\b"),
    ("Clever Control", "monitoring", r"\bclever control\b"),
    ("Controlio", "monitoring", r"\bcontrolio\b"),
    ("Kickidler", "monitoring", r"\bkickidler\b"),
    ("StaffCop", "monitoring", r"\bstaffcop\b"),
    ("CurrentWare (BrowseReporter / AccessPatrol)", "monitoring", r"\bcurrentware\b|\bbrowsereporter\b"),
    ("EmpMonitor", "monitoring", r"\bempmonitor\b"),
    ("Insightful / Workpuls", "monitoring", r"\binsightful\b|\bworkpuls\b"),
    ("Time Doctor", "monitoring", r"\btime ?doctor\b"),
    ("Hubstaff", "monitoring", r"\bhubstaff\b"),
    ("WorkTime", "monitoring", r"\bworktime\b"),
    ("iMonitor", "monitoring", r"\bimonitor (eam|employee|pc)\b"),
    ("FlexiSPY (computer)", "monitoring", r"\bflexispy\b"),
    ("mSpy (computer)", "monitoring", r"\bmspy\b"),
    ("Qustodio", "monitoring", r"\bqustodio\b"),
    ("Net Nanny", "monitoring", r"\bnet ?nanny\b"),
    ("Norton Family", "monitoring", r"\bnorton family\b"),
    ("Kaspersky Safe Kids", "monitoring", r"\bsafe kids\b"),
    ("Bark", "monitoring", r"\bbark (for|desktop)\b"),
    ("Aobo / Aobo Filter", "monitoring", r"\baobo\b"),
    ("WebWatcher", "monitoring", r"\bwebwatcher\b"),
    ("OsMonitor", "monitoring", r"\bosmonitor\b"),
)

ACCESS_PROGRAMS = OWN_ACCESS_PROGRAMS + RMM_PROGRAMS

# The download names of the tools people are most often talked into running ("download AnyDesk and read me the
# code"): (name shown, kind, lowercase file-name pattern). A browser's " (1)" duplicate suffix is removed before
# matching. Used to notice a copy waiting in Downloads, Desktop or Documents that was never installed.
OWN_ACCESS_FILES = (
    ("TeamViewer", "remote", "teamviewerqs*.exe"),
    ("TeamViewer", "remote", "teamviewer_setup*.exe"),
    ("TeamViewer", "remote", "teamviewer*.dmg"),
    ("AnyDesk", "remote", "anydesk*.exe"),
    ("AnyDesk", "remote", "anydesk*.dmg"),
    ("RustDesk", "remote", "rustdesk*.exe"),
    ("RustDesk", "remote", "rustdesk*.dmg"),
    ("Splashtop", "remote", "splashtopsos*.exe"),
    ("Splashtop", "remote", "splashtop_streamer*.exe"),
    ("ConnectWise ScreenConnect / Control", "remote", "screenconnect*.exe"),
    ("ConnectWise ScreenConnect / Control", "remote", "screenconnect*.msi"),
    ("LogMeIn", "remote", "support-logmeinrescue*.exe"),
    ("Zoho Assist", "remote", "za_connect*.exe"),
    ("Supremo", "remote", "supremo*.exe"),
    ("AeroAdmin", "remote", "aeroadmin*.exe"),
    ("Ammyy Admin", "remote", "ammyy*.exe"),
    ("Ammyy Admin", "remote", "aa_v3*.exe"),
    ("Remote Utilities", "remote", "rutserv*.exe"),
    ("LiteManager", "remote", "litemanager*.exe"),
    ("UltraVNC", "remote", "ultravnc*.exe"),
    ("SimpleHelp", "remote", "simplehelpcustomer*.exe"),
    ("UltraViewer", "remote", "ultraviewer*.exe"),
    ("AnyViewer", "remote", "anyviewer*.exe"),
    ("LogMeIn", "remote", "logmeinrescue*.exe"),
    ("GoTo Resolve / GoTo Assist", "remote", "gotoassist*.exe"),
    ("GoTo Resolve / GoTo Assist", "remote", "gotoresolve*.exe"),
    ("Atera agent", "remote", "ateraagent*.msi"),
    ("Atera agent", "remote", "ateraagent*.exe"),
    ("NinjaOne / NinjaRMM agent", "remote", "ninjaone*.msi"),
    ("NinjaOne / NinjaRMM agent", "remote", "ninja*agent*.msi"),
    ("DWService", "remote", "dwagent*.exe"),
    ("ToDesk", "remote", "todesk*.exe"),
    # Linux packages of the tools that ship one, and Mac installer packages.
    ("TeamViewer", "remote", "teamviewer*.deb"),
    ("TeamViewer", "remote", "teamviewer*.rpm"),
    ("TeamViewer", "remote", "teamviewer*.pkg"),
    ("AnyDesk", "remote", "anydesk*.deb"),
    ("AnyDesk", "remote", "anydesk*.rpm"),
    ("RustDesk", "remote", "rustdesk*.deb"),
    ("RustDesk", "remote", "rustdesk*.rpm"),
    ("RustDesk", "remote", "rustdesk*.appimage"),
    ("RustDesk", "remote", "rustdesk*.pkg"),
)

ACCESS_FILES = OWN_ACCESS_FILES + RMM_FILES
