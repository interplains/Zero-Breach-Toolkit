"""Your online accounts, checked with you - and what to do after a threat warning.

No program can see inside your accounts without signing in to them, and this toolkit never signs in to
anything. But the commonest way someone keeps watching a person is not spyware at all: it is a shared or stolen
account - a computer still linked to your WhatsApp, a forwarding rule in your email, your location shared from a
family account. So this is a guided checklist: each step says exactly where to look and what to look for, you
answer, and the result keeps what you checked, what you found and what you skipped (skipped steps are listed as
not checked, never as fine). Nothing is opened, contacted or sent.

  --accounts          the checklist in the terminal (the window has its own, under More checks)
  --threat-warning    what to do after Apple, Google, WhatsApp or another service warns you that you may be targeted
"""
import datetime
import json
import os
from typing import Dict

from .i18n import T

AC_CHECKED, AC_FOUND, AC_SKIPPED = "checked", "found", "skipped"

# (id, account, where to look, what to look for, what to do if something is wrong)
AC_STEPS = (
    ("apple-devices", "Apple Account: devices",
     "iPhone: Settings > [your name], scroll to the list of devices. Or sign in at account.apple.com > Devices.",
     "Every phone, iPad, Mac or Windows computer listed is yours.",
     "Tap the device you don't recognise and choose Remove from Account, then change your Apple Account password."),
    ("apple-safety-check", "Apple: Safety Check",
     "iPhone: Settings > Privacy & Security > Safety Check > Manage Sharing & Access.",
     "Who you share your location, photos, notes and Home with, and which apps can see what.",
     "Stop sharing with anyone you did not choose. If you are in danger, 'Emergency Reset' stops all sharing at "
     "once - but think first about whether the other person will notice."),
    ("google-devices", "Google account: devices",
     "myaccount.google.com/device-activity (or Google app > your picture > Manage your Google Account > Security > "
     "Your devices).",
     "Every device signed in to your Google account is yours.",
     "Choose the device and Sign out, then change your Google password."),
    ("google-access", "Google account: apps with access and recovery",
     "myaccount.google.com/security-checkup.",
     "Third-party apps with access to your account, and the recovery phone number and email.",
     "Remove apps you don't use, and make sure the recovery phone and email are yours alone."),
    ("email-forwarding", "Email: forwarding and rules",
     "Gmail on a computer: Settings > See all settings > 'Forwarding and POP/IMAP' and 'Filters and Blocked "
     "Addresses'. Outlook: Settings > Mail > Forwarding, and Rules.",
     "No forwarding address and no rule you did not create - a quiet way to get a copy of every message.",
     "Delete the forwarding address or rule, then change your email password."),
    ("whatsapp", "WhatsApp: linked devices",
     "WhatsApp > Settings (or the three dots) > Linked devices.",
     "Every computer or tablet listed is yours and in use.",
     "Tap the device and Log out. Whoever linked it could read every message you received while it was linked."),
    ("signal", "Signal: linked devices",
     "Signal > Settings > Linked devices.",
     "Every computer or tablet listed is yours and in use.",
     "Tap the device and Unlink it. Then check Settings > Account > Registration Lock is on."),
    ("telegram", "Telegram: devices",
     "Telegram > Settings > Devices.",
     "Every session listed is yours.",
     "Terminate the session you don't recognise, or 'Terminate all other sessions'."),
    ("meta", "Instagram and Facebook: where you're logged in",
     "Instagram or Facebook > Accounts Center > Password and security > Where you're logged in.",
     "Every phone and computer listed is yours.",
     "Log that device out, change your password and turn on two-step sign-in."),
    ("microsoft", "Microsoft account: devices",
     "account.microsoft.com/devices, and account.microsoft.com/security > Sign-in activity.",
     "Every device and recent sign-in is yours.",
     "Remove the device, and change your Microsoft account password."),
    ("location", "Location sharing",
     "Google Maps > your picture > Location sharing. iPhone: Find My > People. Also any family or safety app "
     "on your phone (Life360 and similar).",
     "You share your location only with people you chose.",
     "Stop sharing with anyone you did not choose. Removing a family app can alert the person who set it up - "
     "plan for that first if you need to."),
    ("phone-number", "Your phone number",
     "Your mobile provider (its app, website or shop).",
     "There is a PIN or port-out lock on your number, so nobody can move it to another SIM and receive your "
     "codes.",
     "Ask your provider to add one. Then use an authenticator app or passkey rather than text-message codes."),
)

# The one piece of advice above all the steps.
AC_KEY_ADVICE = ("The single best thing you can do: use a physical security key, such as a YubiKey, to sign in to "
                 "your most important accounts - your email first, then Google, Apple or Microsoft, then social "
                 "media. Why: a key only works on the real website, so a fake sign-in page gets nothing from it; "
                 "nobody can sign in from far away without holding it in their hand; and unlike text-message codes it "
                 "cannot be stolen by moving your phone number to another SIM. Buy two and add both - one to carry, "
                 "one kept somewhere safe as a spare. Where a service does not take keys, use a passkey or an "
                 "authenticator app instead of text messages.")

# The web page for a step, where there is one (phone apps such as WhatsApp, Signal and Telegram have none).
AC_LINKS = {
    "apple-devices": "https://account.apple.com/account/manage",
    "google-devices": "https://myaccount.google.com/device-activity",
    "google-access": "https://myaccount.google.com/security-checkup",
    "email-forwarding": "https://mail.google.com/mail/u/0/#settings/fwdandpop",
    "meta": "https://accountscenter.facebook.com/password_and_security",
    "microsoft": "https://account.microsoft.com/devices",
    "location": "https://www.google.com/maps/",
}

AC_HOW_TO = ("Checking your online accounts\n\n"
             "No program can see inside your accounts without signing in, and this toolkit never signs in to anything. "
             "But a computer still linked to your WhatsApp, a forwarding rule in your email or a shared location is "
             "a more common way to be watched than spyware. Each step says where to look; you answer:\n"
             "  y = checked, fine     n = something is wrong or missing     s = skip     q = stop")


AC_SAVED = "account-checklist-answers.json"


def ac_load_answers(path: str = "") -> Dict[str, str]:
    """The answers given last time (kept in the program's own folder so a half-done checklist can be finished
    later), or {}."""
    import json
    import os
    from .feeds import default_cache_dir
    path = path or os.path.join(os.path.dirname(default_cache_dir()), AC_SAVED)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {k: v for k, v in data.items() if v in (AC_CHECKED, AC_FOUND, AC_SKIPPED)} if isinstance(data, dict) \
            else {}
    except (OSError, ValueError):
        return {}


def ac_save_answers(answers: Dict[str, str], path: str = "") -> None:
    import json
    import os
    from .feeds import default_cache_dir
    path = path or os.path.join(os.path.dirname(default_cache_dir()), AC_SAVED)
    try:
        if not answers:
            if os.path.exists(path):
                os.remove(path)
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(answers, fh)
        os.replace(path + ".tmp", path)
    except OSError:
        pass


def ac_result(answers: Dict[str, str]) -> Dict[str, object]:
    """The checklist result: every step with its answer; steps not answered count as skipped."""
    steps = []
    for sid, account, _where, _look, fix in AC_STEPS:
        state = answers.get(sid, AC_SKIPPED)
        if state not in (AC_CHECKED, AC_FOUND, AC_SKIPPED):
            state = AC_SKIPPED
        steps.append({"id": sid, "account": account, "state": state, "fix": fix})
    counts = {s: sum(1 for x in steps if x["state"] == s) for s in (AC_CHECKED, AC_FOUND, AC_SKIPPED)}
    level = "worth-a-look" if counts[AC_FOUND] else ("clean" if not counts[AC_SKIPPED] else "incomplete")
    return {"kind": "account-checklist", "made": datetime.datetime.now().replace(microsecond=0).isoformat(),
            "steps": steps, "counts": counts, "level": level}


def ac_headline(result) -> str:
    c = result["counts"]
    if c[AC_FOUND]:
        return T("{n} thing(s) to fix in your accounts - see what to do below", n=c[AC_FOUND])
    if c[AC_SKIPPED]:
        return T("Nothing found in what you checked - {n} step(s) not checked yet", n=c[AC_SKIPPED])
    return T("Every account step checked - nothing you didn't recognise")


from .safetext import safe_render  # noqa: E402


@safe_render
def ac_render(result) -> str:
    import textwrap
    out = ["=" * 72, "  " + T("YOUR ONLINE ACCOUNTS") + "  -  " + ac_headline(result),
           "  " + T("Your own answers; nothing was opened, contacted or sent."), "=" * 72, ""]
    out += textwrap.wrap(T(AC_KEY_ADVICE), 70, initial_indent="  ", subsequent_indent="  ") + [""]
    found = [s for s in result["steps"] if s["state"] == AC_FOUND]
    if found:
        out.append("  " + T("TO FIX - WHAT TO DO"))
        for s in found:
            out += ["    ! " + T(s["account"]), "        " + T(s["fix"])]
        out += [""] + textwrap.wrap(T("Before you remove anything: if someone close to you may be watching, removing "
                                      "their access can alert them. If you are in danger, talk to a helpline first "
                                      "(accessnow.org/help)."), 96, initial_indent="    ", subsequent_indent="    ") + [""]
    checked = [s["account"] for s in result["steps"] if s["state"] == AC_CHECKED]
    if checked:
        out.append("  " + T("CHECKED - FINE"))
        out += ["    - " + T(a) for a in checked]
        out.append("")
    skipped = [s["account"] for s in result["steps"] if s["state"] == AC_SKIPPED]
    if skipped:
        out.append("  " + T("NOT CHECKED (nothing is known about these)"))
        out += ["    - " + T(a) for a in skipped]
        out.append("")
    out.append("  " + T("Also: use a different password for each important account, and two-step sign-in with an "
                        "app or passkey."))
    return "\n".join(out)


def ac_save(result, path: str) -> str:
    """Save the result as JSON (never overwrites an existing file)."""
    if os.path.isdir(path):
        path = os.path.join(path, "account-checklist-{}.json".format(result["made"][:10]))
    if os.path.exists(path):
        raise FileExistsError("{} already exists - choose another name".format(path))
    with open(path, "x", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, ensure_ascii=False)
    return path


# --- after a threat warning -----------------------------------------------------------------------------------------

AC_THREAT_WARNING = """IF YOU GOT A THREAT WARNING

Apple, Google, WhatsApp and Meta warn people they believe were targeted by mercenary spyware or by government-
backed attackers. A warning means you may have been a target - not that an attack worked. Take it seriously,
and take it calmly.

1. MAKE SURE IT IS REAL - without clicking anything in it
   Fake warnings are a known trick. Do not tap links or open files in the message itself.
   - Apple: sign in yourself at account.apple.com - a real warning is also shown at the top of the page there.
     Apple's warnings never ask you to click links, open files, install apps or profiles, or give your password
     or a code.
   - Google: open Gmail on the web yourself (a real warning shows as a banner at the top), and check
     myaccount.google.com > Security.
   - WhatsApp and others: open the app itself, not a link in a message.

2. DO NOT ERASE THE EVIDENCE
   - Do not reset the phone, delete apps or messages, or "clean" it.
   - Keep the warning itself (a screenshot, and the email).

3. SAVE A COPY OF THE PHONE FIRST
   - iPhone: make an encrypted backup on a computer (Finder or Apple Devices / iTunes), and keep its password.
   - Android: make a bug report on the phone (Developer options > Take bug report), or an AndroidQF collection.
   - Check that copy with this toolkit's phone check - and keep it for a helper.

4. THEN PROTECT YOURSELF
   - Install the latest updates (after step 3: an update can remove traces).
   - iPhone: turn on Lockdown Mode (Settings > Privacy & Security > Lockdown Mode).
   - Android: turn on Advanced Protection where your phone has it (Settings > Security & privacy).
   - Google accounts: join Google's Advanced Protection Program.
   - Check your accounts with the account checklist in this toolkit.

5. GET HELP - free, and you do not need to have found anything
   - Access Now Digital Security Helpline - 24/7, many languages: https://www.accessnow.org/help/
   - Amnesty International Security Lab - for journalists, activists and human-rights defenders:
     https://securitylab.amnesty.org/get-help/
   - To send them evidence safely: More checks > Send evidence to a helper.
"""


def ac_terminal(ask, say) -> Dict[str, object]:
    """Walk through the steps with ask(prompt) -> str|None and say(text)."""
    import textwrap
    say("\n".join(textwrap.wrap(T(AC_KEY_ADVICE), 76, initial_indent="  ", subsequent_indent="  ")) + "\n")
    say(T(AC_HOW_TO) + "\n")
    answers = {}
    for i, (sid, account, where, look, _fix) in enumerate(AC_STEPS, 1):
        say("\n  {}  {}\n    {}  {}\n    {}  {}".format(T("{i} of {n}", i=i, n=len(AC_STEPS)), T(account),
                                                       T("Where:"), T(where), T("Check:"), T(look)) +
            ("\n    {}   {}".format(T("Page:"), AC_LINKS[sid]) if sid in AC_LINKS else ""))
        while True:
            reply = ask("    " + T("Your answer (y / n / s / q): "))
            if reply is None:
                reply = "q"
            reply = reply.strip().lower()[:1]
            if reply in ("y", "n", "s", "q"):
                break
        if reply == "q":
            break
        answers[sid] = {"y": AC_CHECKED, "n": AC_FOUND, "s": AC_SKIPPED}[reply]
    return ac_result(answers)


def ac_command(args) -> int:
    """--accounts (interactive checklist) and --threat-warning (the guide)."""
    import sys
    if getattr(args, "threat_warning", False):
        print(T(AC_THREAT_WARNING))
        return 0

    def ask(prompt):
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.readline()
        return line if line else None
    result = ac_terminal(ask, lambda text: print(text))
    print("\n" + ac_render(result))
    return 0                     # a checklist, not a scan: its exit code never says "spyware" or "gaps"
