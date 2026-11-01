"""Generate iocs/curated_mercenary.txt (tab-separated). Every value below was read
from the raw text of the cited Citizen Lab report (2026-10-25), not a summary.
Later additions (2026-10-29: Candiru DevilsTongue and Intellexa Predator from
Microsoft, ESET, Google, Talos, Amnesty and Recorded Future) live in
curated_mercenary_additions.txt beside this file, each value checked verbatim
against its source, and are appended unchanged."""
import io
import sys

OUT = sys.argv[1]
P1 = "citizenlab-paragon-2025-03"   # 'Virtue or Vice? A First Look at Paragon's Proliferating Spyware Operations'
P2 = "citizenlab-paragon-2025-06"   # 'Graphite Caught: First Forensic Confirmation of Paragon's iOS Mercenary Spyware ...'
FAM = "Paragon Graphite"

header = """# Curated mercenary-spyware indicators not available in any machine-readable feed
# as-of: 2026-10-29
# ^ Curated date; the staleness reference for this file.
# Licence: CC0 1.0 (as iocs/LICENSE.md). Indicators are facts; the citations below
#   name the researchers who published them.
# Method: every value was read out of the raw text of the cited report (not from a
#   summary), and its ROLE is recorded from the report's own description.
# Format: indicator <TAB> tier <TAB> confidence <TAB> source-tag <TAB> family
#
# Sources
#   citizenlab-paragon-2025-03  The Citizen Lab, 'Virtue or Vice? A First Look at Paragon's
#       Proliferating Spyware Operations' (2025-03-19).
#       https://citizenlab.ca/research/a-first-look-at-paragons-proliferating-spyware-operations/
#   citizenlab-paragon-2025-06  The Citizen Lab, 'Graphite Caught: First Forensic Confirmation of
#       Paragon's iOS Mercenary Spyware Finds Journalists Targeted' (2025-06-12).
#       https://citizenlab.ca/research/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/
#   microsoft-mstic-2021-07  Microsoft Threat Intelligence Center, 'Protecting customers from a private-sector
#       offensive actor using 0-day exploits and DevilsTongue malware' (2021-07-15).
#       https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/
#   eset-swc-candiru-2021-11  ESET, 'Strategic web compromises in the Middle East with a pinch of Candiru' (2021-11-16).
#       https://www.welivesecurity.com/2021/11/16/strategic-web-compromises-middle-east-pinch-candiru/
#       Values from github.com/eset/malware-ioc (swc-candiru). Copyright (c) ESET spol. s r.o.;
#       BSD-2-Clause, https://github.com/eset/malware-ioc/blob/master/LICENSE
#   gtig-intellexa-2025-12  Google Threat Intelligence Group, 'Intellexa's Prolific Zero-Day Exploits Continue' (2025-12-03).
#       https://cloud.google.com/blog/topics/threat-intelligence/intellexa-zero-day-exploits-continue
#   talos-predator-2023-05  Cisco Talos, 'Mercenary mayhem: A technical analysis of Intellexa's PREDATOR spyware'
#       (2023-05-25). Values from github.com/Cisco-Talos/IOCs (CC0-1.0).
#       https://blog.talosintelligence.com/mercenary-intellexa-predator/
#   amnesty-intellexa-leaks-2025-12  Amnesty International Security Lab, 'To Catch a Predator: Leak exposes the
#       internal operations of Intellexa's mercenary spyware' (2025-12-04).
#       https://securitylab.amnesty.org/latest/2025/12/intellexa-leaks-predator-spyware-operations-exposed/
#   recordedfuture-predator-2025-06  Recorded Future Insikt Group, 'Predator Spyware Resurgence: Insikt Group Exposes
#       New Global Infrastructure' (CTA-2025-0612, June 2025), Appendix A.
#       https://www.recordedfuture.com/research/predator-still-active-new-links-identified
#   google-tag-spyware-vendors-2023-03  Google Threat Analysis Group, 'Spyware vendors use 0-days and
#       n-days against popular platforms' (2023-03-29), 'Related IOCs' of both campaigns.
#       https://blog.google/threat-analysis-group/spyware-vendors-use-0-days-and-n-days-against-popular-platforms/
#
# NOT included, deliberately:
#   - customer-deployment IPs the report publishes only partially (e.g. 67.69.21.xxx);
#   - certificate name 'forti.external-Sht_prd_2.com' (not a valid hostname: underscore);
#   - BIGPRETZEL / SMALLPRETZEL: named forensic indicators whose values are not published.
#"""

rows = []
def add(value, tier, src, note=None):
    if note:
        rows.append("# " + note)
    rows.append("\t".join([value, tier, "primary", src, FAM]))

rows.append("#")
rows.append("# --- Tier 1: victim-facing Graphite servers (devices are expected to contact these)")
add("46.183.184.91", "infrastructure-ip", P2,
    "Server the journalist's iPhone contacted (Jan-Feb 2025, iOS 18.2.1); rented from EDIS Global;"
    " matched Paragon Fingerprint P1 until at least 2025-04-12. Links both cases to one operator.")
add("84.110.122.27", "infrastructure-ip", P1,
    "Tier 1 IP (Fingerprint P1) that also returned cert CN=forti.external-Staging-02.com, Jul-Sep 2023.")
add("178.237.39.204", "infrastructure-ip", P1,
    "Tier 1 IP (Fingerprint P1) that later returned cert CN=awake-wood.io.")
add("awake-wood.io", "infrastructure", P1, "Certificate name seen on Tier 1 IP 178.237.39.204.")
add("forti.external-staging-02.com", "infrastructure", P1,
    "Certificate name seen on Tier 1 IP 84.110.122.27 (lower-cased).")
rows.append("#")
rows.append("# --- Tier 2: Paragon / customer premises (operator side). Ordinary devices are NOT expected")
rows.append("#     to contact these; the names are certificate common names and may not resolve in DNS.")
rows.append("#     Static IPs in Israel that returned Tier 2 certificates (Table 2):")
for last in (82, 83, 84, 85, 86):
    add("84.110.47.%d" % last, "infrastructure-ip", P1)
add("forti.paraccess.com", "infrastructure", P1, "Tier 2 certificate names on the Israeli IPs (Table 2):")
add("modern-money.org", "infrastructure", P1)
add("ancient-thing.it", "infrastructure", P1)
rows.append("#     Certificate names on suspected customer deployments (codename initial matches country):")
for name in ("external-astra.com", "internal-abba.com", "external-cap.com", "external-drt.com",
             "forti.external-muki.com", "external-cag.com", "forti.external-sht.com",
             "forti.external-shotgun3.com", "forti.external-sht-prd-4.com", "forti.internal-stg.com"):
    add(name, "infrastructure", P1)

import os
with io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "curated_mercenary_additions.txt"),
             encoding="utf-8") as fh:
    additions = fh.read()
with io.open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(header + "\n" + "\n".join(rows) + "\n" + additions)
print("wrote", OUT, sum(1 for r in rows if not r.startswith("#"))
      + sum(1 for r in additions.splitlines() if r and not r.startswith("#")), "indicators")
