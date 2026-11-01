"""Installed iPhone configuration profiles that can control the phone or its
traffic (device management, a trusted root certificate, VPN, proxy, DNS) are
listed as leads with their name and install date; harmless ones are not."""
import datetime
import plistlib

from test_ios_upgrade import backup, ctx, reader  # noqa: F401  (reader is a fixture)
from test_followup_fixes import bundle  # noqa: F401  (fixture)


def test_management_profile_is_a_lead(tmp_path, reader):
    root = tmp_path / "backup"
    managed = {"PayloadDisplayName": "Device Care", "PayloadOrganization": "Example Org",
               "PayloadRemovalDisallowed": True, "InstallDate": datetime.datetime(2026, 3, 1, 9, 0),
               "PayloadUUID": "11111111-2222-3333-4444-555555555555",
               "PayloadContent": [{"PayloadType": "com.apple.mdm"}, {"PayloadType": "com.apple.security.root"}]}
    harmless = {"PayloadDisplayName": "Wallpaper", "PayloadUUID": "66666666-7777-8888-9999-000000000000",
                "PayloadContent": [{"PayloadType": "com.apple.wallpaper"}]}
    backup(root, [("HomeDomain", "Library/ConfigurationProfiles/profile-aaaa.stub", plistlib.dumps(managed)),
                  ("HomeDomain", "Library/ConfigurationProfiles/profile-bbbb.stub", plistlib.dumps(harmless))])
    result = reader(ctx(root))
    leads = [l for l in result.leads if l.check == "ios:configuration-profiles"]
    assert len(leads) == 1
    lead = leads[0]
    assert "Device Care" in lead.what and "Example Org" in lead.what
    assert "device management" in lead.what and "root certificate" in lead.what and "cannot be removed" in lead.what
    assert lead.observed.startswith("2026-03-01") and "work or school" in lead.usual_reason
    assert result.hits == [] or all(h.evidence != "on-device" for h in result.hits)
