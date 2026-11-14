"""What happened? The situations people are in, each leading to the check that answers it.

Only a guide: every choice opens a check the program already has. Shared by the window and the terminal menu so the
two never disagree. Options on the command line skip it entirely.
"""

# (key, what happened - in the person's words, what will happen next, terminal menu entry it opens)
INTAKE = (
    ("file", "I got a file I'm not sure about",
     "We look at the file without opening it. Nothing is changed or sent.", "A suspicious file"),
    ("link", "I got a link or a message I'm not sure about",
     "Paste it and we read it without opening the link.", "A link or message"),
    ("warning", "I got a security warning (Apple, Google, WhatsApp...)",
     "What to do, in the order that keeps the evidence.", "I got a threat warning"),
    ("taken", "My phone was taken from me or out of my sight",
     "We look for signs that a forensics tool copied it.", "Was a phone copied?"),
    ("partner", "Someone seems to know things they shouldn't",
     "A safety note first, then the phone check and your accounts.", "A phone"),
    ("network", "There's a network or device I don't recognise",
     "Hidden Wi-Fi networks nearby and what they probably are. Joins nothing.", "Hidden Wi-Fi networks nearby"),
    ("checkup", "I just want a check-up",
     "The standard check of this computer.", "This computer - standard check"),
)

INTAKE_PARTNER_NOTE = (
    "Before you change anything: if someone close to you may be watching your phone or accounts, removing an app or "
    "changing a password can alert them. If that could put you at risk, talk to a helpline first - the Coalition "
    "Against Stalkerware lists free services: https://stopstalkerware.org/ . The checks below only look; they "
    "change nothing.")
