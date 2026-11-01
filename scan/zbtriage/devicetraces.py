"""Phone traces that researchers published which are not addresses or file
fingerprints: phone settings, file locations, process names, identifiers of the
computer a phone was plugged into, and the fake USB devices a phone-forensics
tool imitates.

They are kept out of the indicator lists on purpose. A list entry is matched
everywhere its type is used: a three-letter process name like "mnm" would also
be compared with programs on a Mac or Linux computer, where it means nothing.
Each trace here is matched only by the phone check it was published for.

Every value was copied from the cited report's own text; none is inferred.
"""

import re

from .iocs import Indicator

# Source tags, as printed in reports. Their citations are in DT_SOURCES.
DT_AMNESTY_CELLEBRITE = "amnesty-cellebrite-serbia-2025-02"
DT_CITIZENLAB_CELLEBRITE = "citizenlab-cellebrite-jordan-2026-01"
DT_GOOGLE_VARISTON = "google-tag-spyware-vendors-2023-03"

DT_SOURCES = {
    DT_AMNESTY_CELLEBRITE: (
        "Amnesty International Security Lab, 'Cellebrite zero-day exploit used to target phone of "
        "Serbian student activist' (2025-02-28)",
        "https://securitylab.amnesty.org/latest/2025/02/cellebrite-zero-day-exploit-used-to-target-"
        "phone-of-serbian-student-activist/"),
    DT_CITIZENLAB_CELLEBRITE: (
        "The Citizen Lab, 'From Protest to Peril: Cellebrite Used Against Jordanian Civil Society' "
        "(2026-01-22), Appendix: Indicators of Compromise",
        "https://citizenlab.ca/research/from-protest-to-peril-cellebrite-used-against-jordanian-civil-society/"),
    DT_GOOGLE_VARISTON: (
        "Google Threat Analysis Group, 'Spyware vendors use 0-days and n-days against popular "
        "platforms' (2023-03-29), Campaign #2 'Related IOCs'",
        "https://blog.google/threat-analysis-group/spyware-vendors-use-0-days-and-n-days-against-popular-platforms/"),
}

CELLEBRITE = "Cellebrite (phone-forensics tool)"
VARISTON = "Variston Heliconia"

# --- Android -------------------------------------------------------------------

# Google TAG: the Android spyware delivered by the Heliconia exploit chain set
# these system properties and used this folder.
DT_ANDROID_PROPERTIES = ("sys.brand.note", "sys.brand.notes", "sys.brand.doc")
DT_ANDROID_PATHS = ("/data/local/tmp/dropbox",)

# Amnesty: Cellebrite's unlocking hardware imitates these USB devices, each of
# which reaches an unusual code path in a Linux kernel driver. Every one it
# imitated reported the device version 12.34 - "a strong indicator of
# emulation rather than genuine hardware". Real devices with these ids exist
# (a Microsoft mouse, a webcam, sound cards), so the id alone is never enough:
# only the id together with version 12.34 is reported.
DT_CELLEBRITE_USB = {
    ("045e", "076c"): "a 'HID Device' imitating a Microsoft Comfort Mouse 4500",
    ("04f2", "b071"): "a 'Video Device' imitating a Chicony CNF7129 webcam",
    ("1130", "3101"): "a touch pad imitating an Anton Touch Pad",
    ("041e", "3000"): "a 'Sound Device' imitating a Creative Extigy sound card",
    ("0763", "2012"): "a 'Sound Device' imitating an M-Audio Fast Track Pro",
}
DT_CELLEBRITE_USB_VERSION = "12.34"

# Android's USB host service logs each attached device as
#   USB device attached: vidpid 04f2:b071 mfg/product/ver/serial Video/Video Device/12.34/00001
# and kernel device events name it as PRODUCT=4f2/b071/1234 (version in BCD).
_DT_USB_ATTACHED = re.compile(
    r"USB device attached: vidpid ([0-9a-fA-F]{4}):([0-9a-fA-F]{4}) "
    r"mfg/product/ver/serial [^/\r\n]*/[^/\r\n]*/([^/\r\n]*)/")
_DT_USB_PRODUCT = re.compile(r"(?<![0-9A-Za-z/])([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})/1234(?![0-9A-Za-z])")


def dt_android_usb(text):
    """Cellebrite's imitated USB devices in Android log text, as
    [(vid, pid, line number)], one entry per line that names one."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if "1234" not in line and "12.34" not in line:
            continue
        for match in _DT_USB_ATTACHED.finditer(line):
            vid, pid = match.group(1).lower(), match.group(2).lower()
            if (vid, pid) in DT_CELLEBRITE_USB and match.group(3).strip() == DT_CELLEBRITE_USB_VERSION:
                found.append((vid, pid, number))
        for match in _DT_USB_PRODUCT.finditer(line):
            vid, pid = match.group(1).lower().zfill(4), match.group(2).lower().zfill(4)
            if (vid, pid) in DT_CELLEBRITE_USB:
                found.append((vid, pid, number))
    return found


def dt_usb_indicator(vid, pid):
    return Indicator("cellebrite usb {}:{}".format(vid, pid),
                     "forensic", "primary", "usb-device", DT_AMNESTY_CELLEBRITE, CELLEBRITE)


def dt_android_property_indicators():
    return [Indicator(p, "artifact", "primary", "android-property", DT_GOOGLE_VARISTON, VARISTON)
            for p in DT_ANDROID_PROPERTIES]


def dt_android_path_indicators():
    return [Indicator(p, "artifact", "primary", "file-path", DT_GOOGLE_VARISTON, VARISTON)
            for p in DT_ANDROID_PATHS]


# --- iPhone --------------------------------------------------------------------

# Citizen Lab: a crash log showed a process called "mnm" whose dispatch queue was
# labelled "com.cellebrite.bruteforce"; both attributed to Cellebrite with high
# confidence. The lockdown records name the computer the phone was connected to;
# the same Host ID was found on several other seized iPhones.
DT_IOS_PROCESS = "mnm"
DT_IOS_STRINGS = {
    "com.cellebrite.bruteforce": ("dispatch-queue", "Cellebrite's password brute-force task"),
    "9016926980658937761372207": ("lockdown-host-id", "the Host ID of a Cellebrite computer"),
    "30313996-42072961236303456": ("lockdown-buid", "the System BUID of a Cellebrite computer"),
}


def dt_ios_process_indicator():
    return Indicator(DT_IOS_PROCESS, "forensic", "primary", "process", DT_CITIZENLAB_CELLEBRITE, CELLEBRITE)


def dt_ios_string_indicators():
    return [(value, Indicator(value, "forensic", "primary", kind, DT_CITIZENLAB_CELLEBRITE, CELLEBRITE), what)
            for value, (kind, what) in DT_IOS_STRINGS.items()]


def dt_ios_strings_in(text):
    """[(indicator, what)] for each Cellebrite string the text contains."""
    return [(ind, what) for value, ind, what in dt_ios_string_indicators() if value in text]
