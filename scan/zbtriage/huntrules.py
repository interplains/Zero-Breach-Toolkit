"""What to look for in Windows' own records: our own rule set, written for this toolkit.

Each rule names a log, the event numbers it applies to, and conditions on the event's fields. It is deliberately
aimed at how someone takes and keeps control of a person's computer - remote access, hidden commands, protection
switched off, records wiped - rather than at the whole of attacker behaviour, and every rule says in plain words
what it means and what is normal.

  where     the log (channel) the event comes from; "*" for any
  ids       event numbers, or () for any
  all       every one of these must match
  any       at least one of these must match
  none      none of these may match (what normal use looks like)
  level     "known" (this is how an attack looks), "look" (worth a look), "info" (context only)

A condition is (field, test, value): fields are read from the event's data, plus "Text" for everything the event
says. Tests: "has" (contains, ignoring case), "is", "starts", "ends", "re" (regular expression), "empty".
"""
from __future__ import annotations

HR_KNOWN, HR_LOOK, HR_INFO = "known", "look", "info"

# Channels worth collecting, and whether they usually need administrator rights.
HR_CHANNELS = (
    ("Microsoft-Windows-PowerShell/Operational", False),
    ("Windows PowerShell", False),
    ("Microsoft-Windows-TaskScheduler/Operational", False),
    ("Microsoft-Windows-WMI-Activity/Operational", False),
    ("Microsoft-Windows-Windows Defender/Operational", False),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", False),
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", False),
    ("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", False),
    ("Microsoft-Windows-Bits-Client/Operational", False),
    ("Microsoft-Windows-CodeIntegrity/Operational", False),
    ("Microsoft-Windows-AppLocker/EXE and DLL", False),
    ("Microsoft-Windows-Sysmon/Operational", False),
    ("System", False),
    ("Application", False),
    ("Security", True),
)

# Words that mean "fetch something from the internet and run it" in a command line.
_HR_DOWNLOAD = (r"(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|\birm\b|"
                r"invoke-restmethod|\bcurl\b|\bwget\b|start-bitstransfer|bitsadmin\s+/transfer|"
                r"certutil\s+(-|/)urlcache|certutil\s+(-|/)decode|msiexec\s+/i\s+http)")
_HR_HIDDEN = r"(?i)(-e(nc|ncodedcommand|c)\s+[A-Za-z0-9+/=]{30,}|frombase64string|-w\s+hidden|-windowstyle\s+hidden)"
_HR_AMSI = (r"(?i)(amsiutils|amsiinitfailed|amsiscanbuffer|\[ref\]\.assembly\.gettype|"
            r"system\.management\.automation\.amsi)")
_HR_MEMORY = (r"(?i)(virtualalloc|writeprocessmemory|createremotethread|ntmapviewofsection|"
              r"reflection\.assembly\]::load|\[reflection\.assembly\]::load|memorystream.*deflatestream)")

HR_RULES = (
    # --- PowerShell ------------------------------------------------------------------------------------------
    {"id": "ps-hidden-encoded", "where": "*", "ids": (4103, 4104, 400, 403, 600, 800),
     "any": [("Text", "re", _HR_HIDDEN)], "level": HR_LOOK,
     "says": "a PowerShell command was run in a hidden window or with its text encoded",
     "means": "Encoding hides what a command does. Installers and some management software do it too, so read "
              "the command itself: it is written out in full below."},
    {"id": "ps-download-run", "where": "*", "ids": (4103, 4104, 400, 403, 600, 800),
     "any": [("Text", "re", _HR_DOWNLOAD)], "level": HR_LOOK,
     "says": "a command fetched something from the internet",
     "means": "This is how most computers are taken over: a short command downloads the real program. Check the "
              "address it used and whether you recognise it."},
    {"id": "ps-amsi", "where": "*", "ids": (4103, 4104, 600, 800),
     "any": [("Text", "re", _HR_AMSI)], "level": HR_KNOWN,
     "says": "a command tried to switch off Windows' script checking (AMSI)",
     "means": "There is no ordinary reason to do this. It is done to stop Windows noticing what runs next."},
    {"id": "ps-memory-load", "where": "*", "ids": (4103, 4104, 600, 800),
     "any": [("Text", "re", _HR_MEMORY)], "level": HR_KNOWN,
     "says": "a command loaded a program straight into memory",
     "means": "Running a program without ever writing it to disk is a way to leave nothing behind for a scan to "
              "find. Some developer tools do this; on an ordinary computer it is a strong sign."},
    {"id": "ps-logging-off", "where": "*", "ids": (4103, 4104),
     "any": [("Text", "re", r"(?i)(scriptblocklogging.*(0|false)|set-mppreference.*disable|"
                            r"remove-item.*scriptblocklogging)")], "level": HR_KNOWN,
     "says": "a command tried to switch off PowerShell's own record-keeping",
     "means": "Switching off the record of what runs is what someone does to cover their tracks."},
    {"id": "ps-remote", "where": "*", "ids": (4103, 4104, 600),
     "any": [("Text", "re", r"(?i)(enter-pssession|new-pssession|invoke-command\s+-computername|"
                            r"enable-psremoting|winrs\s+-r)")], "level": HR_LOOK,
     "says": "PowerShell was used to reach another computer, or this one was opened to remote commands",
     "means": "Normal in an office. On a personal computer, someone may have opened a way in."},

    # --- scheduled tasks -------------------------------------------------------------------------------------
    {"id": "task-new", "where": "Microsoft-Windows-TaskScheduler/Operational", "ids": (106,),
     "level": HR_INFO, "says": "a new scheduled task was created",
     "means": "Tasks are the usual way a program arranges to start again after a restart. Compare the list with "
              "'What starts automatically'."},
    {"id": "task-deleted", "where": "Microsoft-Windows-TaskScheduler/Operational", "ids": (141,),
     "level": HR_LOOK, "says": "a scheduled task was deleted",
     "means": "Uninstalling software deletes its tasks. A task deleted on its own can also be someone tidying up "
              "after themselves."},
    {"id": "task-runs-script-host", "where": "Microsoft-Windows-TaskScheduler/Operational", "ids": (129, 100, 200),
     "any": [("Text", "re", r"(?i)(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|curl|bitsadmin)")],
     "level": HR_LOOK, "says": "a scheduled task started a script or a command interpreter",
     "means": "Normal for backup and maintenance tools. It is also the most common way spyware starts itself, so "
              "check the task's name and what it runs."},

    # --- WMI -------------------------------------------------------------------------------------------------
    {"id": "wmi-persistence", "where": "Microsoft-Windows-WMI-Activity/Operational", "ids": (5861,),
     # Windows registers this one itself (Service Control Manager writes to the event log through it): only the
     # exact built-in pair, and only when nothing in it runs a command or a script (team test F2).
     "none": [("Text", "re", r"(?is)^(?!.*(?:CommandLineEventConsumer|ActiveScriptEventConsumer))"
                             r"(?=.*SCM Event Log Filter)(?=.*NTEventLogEventConsumer=\"SCM Event Log Consumer\")")],
     "level": HR_KNOWN, "says": "a permanent WMI subscription was registered",
     "means": "This makes Windows itself run something whenever a chosen thing happens - a hiding place that "
              "survives restarts and shows up in no startup list. Management software (SCCM) uses it too."},
    {"id": "wmi-process", "where": "Microsoft-Windows-WMI-Activity/Operational", "ids": (5857, 5858, 5860),
     "any": [("Text", "re", r"(?i)(win32_process.*create|win32_shadowcopy|win32_service.*create)")],
     "level": HR_LOOK, "says": "WMI was used to start a program or make a shadow copy",
     "means": "A way to start programs that does not look like an ordinary launch. Backup software does the "
              "shadow-copy part legitimately."},

    # --- services and drivers --------------------------------------------------------------------------------
    {"id": "service-installed", "where": "System", "ids": (7045, 7030, 7040),
     "level": HR_INFO, "says": "a service was installed or changed",
     "means": "Remote-access and monitoring tools install a service so they start before anyone signs in. Check "
              "the name against software you installed yourself."},
    {"id": "service-user-path", "where": "System", "ids": (7045,),
     "any": [("Text", "re", r"(?i)(\\users\\|\\appdata\\|\\temp\\|\\programdata\\|\\public\\)")],
     "level": HR_LOOK, "says": "a service or driver was installed from a personal or temporary folder",
     "means": "Real software installs into Program Files, so this is worth reading. Some hardware-information "
              "and overclocking tools genuinely load their driver from a temporary folder, and so does spyware "
              "that wants full rights over the computer. Check the name against software you installed."},
    {"id": "driver-blocked-file", "where": "Microsoft-Windows-CodeIntegrity/Operational", "ids": (3004,),
     "level": HR_LOOK, "says": "Windows refused a file because its signature did not check out",
     "means": "Old or home-made software does this. So does a file that was tampered with after it was signed."},
    {"id": "driver-blocked-load", "where": "Microsoft-Windows-CodeIntegrity/Operational", "ids": (3033, 3077),
     "level": HR_INFO, "says": "Windows stopped one program loading another because of its signature",
     "means": "Mostly routine: Windows Update and graphics drivers trip this constantly. Worth a glance only if "
              "the file named is one you do not recognise."},

    # --- protection switched off -----------------------------------------------------------------------------
    {"id": "defender-off", "where": "Microsoft-Windows-Windows Defender/Operational", "ids": (5001, 5010, 5012),
     "level": HR_LOOK, "says": "Windows' own protection was switched off or limited",
     "means": "Installing another antivirus does this on purpose. If you did not do it and no other antivirus is "
              "installed, someone wanted their program to run unnoticed."},
    {"id": "defender-tamper", "where": "Microsoft-Windows-Windows Defender/Operational", "ids": (5013,),
     "level": HR_LOOK, "says": "something tried to change Windows' protection and Windows undid it",
     "means": "This is Windows defending itself, so the change did not stick - but something did try. Read the "
              "setting named, and check what else happened around that time."},
    {"id": "defender-exclusion", "where": "*", "ids": (5007,),
     "any": [("Text", "re", r"(?i)Exclusions\\(Paths|Extensions|Processes|IpAddresses)")],
     "none": [("Text", "has", r"Exclusions\TemporaryPaths")], "level": HR_LOOK,
     "says": "a folder, file type or program was added to Windows' 'do not scan' list",
     "means": "Games, development tools and some installers add exclusions for speed, so read the path. If you "
              "do not recognise it, whatever sits there is being kept away from scanning on purpose - which is "
              "one of the first things someone does before leaving spyware behind."},
    {"id": "defender-found", "where": "Microsoft-Windows-Windows Defender/Operational", "ids": (1006, 1007, 1008,
                                                                                               1116, 1117, 1118),
     "level": HR_LOOK, "says": "Windows found something and acted on it",
     "means": "Read the name and the path: it says what was found and whether it was removed. Something removed "
              "once can have been put back."},

    # --- the records themselves ------------------------------------------------------------------------------
    {"id": "log-cleared", "where": "*", "ids": (1102, 104),
     "level": HR_KNOWN, "says": "an event log was cleared",
     "means": "Windows keeps this one line about its own records being wiped. Clearing a log is not something "
              "that happens by itself, and it is the clearest sign someone was covering their tracks."},
    {"id": "time-changed", "where": "Security", "ids": (4616,),
     "none": [("ProcessName", "re", r"(?i)(w32time|svchost|vmtoolsd|systemsettings)")], "level": HR_LOOK,
     "says": "the computer's clock was changed by a program",
     "means": "Changing the clock makes records harder to line up. Windows' own time service does it normally."},

    # --- remote access ---------------------------------------------------------------------------------------
    {"id": "rdp-session", "where": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
     "ids": (21, 22, 25), "level": HR_INFO, "says": "someone signed in over Remote Desktop",
     "means": "If nobody should be able to reach this computer remotely, every one of these matters. The address "
              "they came from is shown."},
    {"id": "rdp-outside", "where": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "ids": (131,),
     "level": HR_LOOK, "says": "a Remote Desktop connection arrived from another address",
     "means": "Someone or something tried to reach this computer's desktop over the network."},
    {"id": "bits-transfer", "where": "Microsoft-Windows-Bits-Client/Operational", "ids": (3, 59, 60),
     "level": HR_INFO, "says": "Windows' background download service fetched something",
     "means": "Windows Update uses this constantly. It is also a quiet way to download a program, so the address "
              "is worth reading."},

    # --- signing in ------------------------------------------------------------------------------------------
    {"id": "logon-network", "where": "Security", "ids": (4624,),
     "all": [("LogonType", "is", "3")],
     "none": [("TargetUserName", "ends", "$"), ("TargetUserName", "re", r"(?i)^(anonymous logon|system|"
                                                                        r"local service|network service)$")],
     "level": HR_INFO, "says": "an account signed in over the network",
     "means": "File sharing and home network devices do this. A name you do not know, or many in a row, is worth "
              "a look."},
    {"id": "logon-failures", "where": "Security", "ids": (4625,), "level": HR_INFO,
     "says": "a sign-in failed", "means": "A few are normal typing mistakes. Many in a short time means someone "
                                          "was guessing a password."},
    {"id": "new-user", "where": "Security", "ids": (4720, 4732, 4728),
     "level": HR_LOOK, "says": "an account was created, or added to a powerful group",
     "means": "A new account, or an existing one given administrator rights, is how access is kept after the way "
              "in is closed."},

    # --- Sysmon, when it is installed -------------------------------------------------------------------------
    {"id": "sysmon-process", "where": "Microsoft-Windows-Sysmon/Operational", "ids": (1,),
     "any": [("CommandLine", "re", _HR_DOWNLOAD), ("CommandLine", "re", _HR_HIDDEN)], "level": HR_LOOK,
     "says": "a program was started with a hidden or downloading command line",
     "means": "Sysmon records every program that starts. This one's command line fetches something or hides "
              "itself."},
    {"id": "sysmon-rare-parent", "where": "Microsoft-Windows-Sysmon/Operational", "ids": (1,),
     "all": [("ParentImage", "re", r"(?i)\\(winword|excel|powerpnt|outlook|acrord32|msaccess)\.exe$"),
             ("Image", "re", r"(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$")],
     "level": HR_KNOWN, "says": "a document opened a command interpreter",
     "means": "Word, Excel and PDF readers do not normally start PowerShell or the command prompt. This is what "
              "a booby-trapped document does when it is opened."},
    {"id": "sysmon-autostart", "where": "Microsoft-Windows-Sysmon/Operational", "ids": (12, 13),
     "any": [("TargetObject", "has", "CurrentVersion\\Run"), ("TargetObject", "has", "Winlogon"),
             ("TargetObject", "has", "Image File Execution Options")], "level": HR_LOOK,
     "says": "something wrote to one of the places Windows starts programs from",
     "means": "Installers do this once. The same place changed by a program you do not recognise is how spyware "
              "arranges to come back."},
)


def hr_rules_for(channel: str):
    return [r for r in HR_RULES if r["where"] in ("*", channel)]


HR_IDS_BY_CHANNEL = {}
for _rule in HR_RULES:
    for _channel in ([_rule["where"]] if _rule["where"] != "*" else [c for c, _a in HR_CHANNELS]):
        HR_IDS_BY_CHANNEL.setdefault(_channel, set()).update(_rule["ids"])
del _rule, _channel
