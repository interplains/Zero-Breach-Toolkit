ZERO BREACH TOOLKIT - HOW TO OPEN IT ON A MAC

The program is not signed by Apple (signing needs a paid account in a real
person's name, and this project is anonymous), so macOS will stop it the first
time you open it. That is expected. You only need to do this once.

1. Double-click "Zero Breach Toolkit". macOS says it cannot verify it.
   Click "Done" (or "OK").
2. Open System Settings > Privacy & Security. Scroll down to the message about
   "Zero Breach Toolkit" and click "Open Anyway". Enter your password.
3. Double-click "Zero Breach Toolkit" again and click "Open".

It opens in a Terminal window with a menu. Press Enter for the standard check.

To let it check Safari: System Settings > Privacy & Security > Full Disk Access,
click +, choose Applications > Utilities > Terminal, and turn it on.

Check the download first if you can: compare its SHA-256 with the release page,
or run  gh attestation verify <file> --repo interplains/Zero-Breach-Toolkit
Guide: https://github.com/interplains/Zero-Breach-Toolkit#readme
