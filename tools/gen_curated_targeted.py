"""Generate iocs/curated_targeted.txt (tab-separated): spyware used against
journalists, activists, human-rights defenders and minorities, from researchers'
own indicator files.

The values live in curated_targeted_values.txt beside this file. Each block there
names the publisher file it was copied from; only SHA-256 file fingerprints and
Android package names are taken. Network addresses from these reports are left out
on purpose: most are several years old, and an old domain or address may now
belong to someone innocent."""
import io
import os
import sys

OUT = sys.argv[1]

header = """# Spyware used against journalists, activists, human-rights defenders and minorities
# as-of: 2026-11-01
# ^ Curated date; the staleness reference for this file.
# Licence: the selection is CC0 1.0 (as iocs/LICENSE.md). The values are facts published by
#   the researchers named below. Where a publisher's repository carries a licence, its notice
#   is kept here and its terms still apply to the values copied from it.
# Method: every value was copied from the publisher's own indicator file (or, for the package
#   names marked so, the report's own sample table) and checked for shape. Only SHA-256 file
#   fingerprints and Android package names are included: no domains, no IP addresses.
#   Package names that another developer could plausibly use, or that belong to a real app
#   the spyware imitated, are left out; those samples are still matched by fingerprint.
# Format: indicator <TAB> tier <TAB> confidence <TAB> source-tag <TAB> family [<TAB> kind]
#   (kind is given only for package names: app-id)
#
# Sources
#   eset-aridspy-2024-06  ESET, 'Arid Viper poisons Android apps with AridSpy' (2024-06-13).
#       https://www.welivesecurity.com/en/eset-research/arid-viper-poisons-android-apps-with-aridspy/
#       Fingerprints from github.com/eset/malware-ioc (aridspy/samples.sha256); package names
#       from the report's sample tables.
#   talos-aridviper-2023-10  Cisco Talos, 'Arid Viper disguising mobile spyware as updates for
#       non-malicious Android applications' (2023-10-31).
#       https://github.com/Cisco-Talos/IOCs/blob/main/2023/10/arid-viper-mobile-spyware.txt (CC0-1.0)
#   sentinel-spyc23-2023-10  SentinelLabs, 'Arid Viper | APT's Nest of SpyC23 Malware Continues to
#       Target Android Devices' (2023-10-24). Package names from the report text.
#       https://www.sentinelone.com/labs/arid-viper-apts-nest-of-spyc23-malware-continues-to-target-android-devices/
#   meta-palestine-2021-04  Meta, 'Taking Action Against Hackers in Palestine' (2021-04-21):
#       Palestinian Preventive Security Service malware, sha256 rows only.
#       https://github.com/facebook/threat-research/blob/main/indicators/csv/2021_04_taking_action_against_hackers_in_palestine.csv
#       Meta threat-research data is provided under the MIT License, Copyright (c) Meta Platforms, Inc. and its affiliates.
#   volexity-evilbamboo-2023-09  Volexity, EvilBamboo (2023-09-22): BADBAZAAR, BADSOLAR and
#       BADSIGNAL, used against Tibetan, Uyghur and Taiwanese people.
#       https://github.com/volexity/threat-intel/tree/main/2023/2023-09-22%20EvilBamboo
#   volexity-uta0560-2026-09  Volexity, Chrome exploit chain sent by UTA0560 (2026-09-09).
#       https://github.com/volexity/threat-intel/tree/main/2026/2026-09-09%20Chrome
#   volexity-brazenbamboo-2024-11  Volexity, BrazenBamboo: LIGHTSPY and DEEPDATA (2024-11-15).
#       https://github.com/volexity/threat-intel/tree/main/2024/2024-11-15%20BrazenBamboo
#       Volexity values: Copyright 2022 by Volexity, Inc.; BSD-2-Clause,
#       https://github.com/volexity/threat-intel/blob/main/LICENSE.txt
#   unit42-henbox-2018-03  Palo Alto Networks Unit 42, HenBox Android spyware used against Uyghurs
#       (March 2018). https://github.com/pan-unit42/iocs/blob/master/henbox/henbox_samples.csv
#       Copyright (c) 2018 Palo Alto Networks; MIT License,
#       https://github.com/pan-unit42/iocs/blob/master/LICENSE
#   lookout-bonespy-2024-12  Lookout, BoneSpy (December 2024).
#       https://github.com/lookout/threat-intelligence/blob/main/2024/bonespy_dec_2024.csv
#   lookout-plaingnome-2024-12  Lookout, PlainGnome (December 2024).
#       https://github.com/lookout/threat-intelligence/blob/main/2024/plaingnome_dec_2024.csv
#       Lookout values: Apache License 2.0, https://github.com/lookout/threat-intelligence/blob/main/LICENSE
#   eset-ghostchat-2026-01  ESET, 'Love? Actually: Fake dating app used as lure in targeted spyware
#       campaign in Pakistan' (January 2026). https://github.com/eset/malware-ioc/tree/master/ghostchat
#   eset-kamran-2023-11  ESET, 'Unlucky Kamran: Android malware spying on Urdu-speaking residents of
#       Gilgit Baltistan' (November 2023).
#       https://www.welivesecurity.com/en/eset-research/unlucky-kamran-android-malware-spying-urdu-speaking-residents-gilgit-baltistan/
#   eset-vajraspy-2024-01  ESET, 'VajraSpy: A Patchwork of espionage apps' (January 2024).
#       https://www.welivesecurity.com/en/eset-research/vajraspy-patchwork-espionage-apps
#   eset-exoticvisit-2024-03  ESET, 'eXotic Visit campaign: Tracing the footprints of Virtual
#       Invaders' (March 2024).
#       https://www.welivesecurity.com/en/eset-research/exotic-visit-campaign-tracing-footprints-virtual-invaders/
#   eset-gravityrat-2023-06  ESET, 'Android GravityRAT goes after WhatsApp backups' (2023-06-15).
#       https://www.welivesecurity.com/2023/06/15/android-gravityrat-goes-after-whatsapp-backups/
#   eset-dazzlespy-2022-01  ESET, 'Watering hole deploys new macOS malware, DazzleSpy, in Asia'
#       (2022-01-25). https://www.welivesecurity.com/2022/01/25/watering-hole-deploys-new-macos-malware-dazzlespy-asia/
#   eset-scarcruft-dolphin-2022-11  ESET, 'Who's swimming in South Korean waters? Meet ScarCruft's
#       Dolphin' (2022-11-30).
#       https://www.welivesecurity.com/2022/11/30/whos-swimming-south-korean-waters-meet-scarcrufts-dolphin/
#   eset-scarcruft-birdcall-2026-05  ESET, 'A rigged game: ScarCruft compromises gaming platform in a
#       supply-chain attack' (May 2026). https://github.com/eset/malware-ioc/tree/master/scarcruft
#       ESET values: Copyright (c) 2014-2018 ESET spol. s r.o.; BSD-2-Clause,
#       https://github.com/eset/malware-ioc/blob/master/LICENSE
#   amnesty-donot-togo-2021-10  Amnesty International, 'Hackers-for-hire in West Africa: Activists in
#       Togo Attacked with Indian-made Spyware' (2021-10-07).
#       https://github.com/AmnestyTech/investigations/tree/master/2021-10-07_donot
#   amnesty-oceanlotus-vietnam-2021-02  Amnesty International, 'Click and Bait: Vietnamese Human Rights
#       Defenders Targeted with Spyware Attacks' (2021-02-24).
#       https://github.com/AmnestyTech/investigations/tree/master/2021-02-24_vietnam
#   amnesty-netwire-india-2020-06  Amnesty International, 'India: Human Rights Defenders Targeted by a
#       Coordinated Spyware Operation' (2020-06-15).
#       https://github.com/AmnestyTech/investigations/tree/master/2020-06-15_india
#       Amnesty values are shared under CC BY 2.0 (https://creativecommons.org/licenses/by/2.0/);
#       credit: Amnesty International Security Lab.
#
# NOT included, deliberately:
#   - domains, IP addresses, URLs and e-mail addresses from these reports (old ones may now
#     belong to someone innocent);
#   - SHA-1 and MD5 values (the check computes SHA-256 only);
#   - Volexity BrazenBamboo rows named after ordinary Windows or Chromium libraries, and the
#     rows of a second actor in the 2026-09-09 Chrome file.
#"""

here = os.path.dirname(os.path.abspath(__file__))
with io.open(os.path.join(here, "curated_targeted_values.txt"), encoding="utf-8") as fh:
    values = fh.read()
with io.open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(header + "\n" + values)
print("wrote", OUT, sum(1 for r in values.splitlines() if r and not r.startswith("#")), "indicators")
