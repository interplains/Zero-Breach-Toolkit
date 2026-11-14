"""How much of each language is translated.

    python tools/translation_report.py            # one line per language
    python tools/translation_report.py fr         # also list the sentences French is missing

Counts the sentences in locales/en.json that each other locale does not have; a missing sentence is shown
in English. Information only: always exits 0. On GitHub Actions the table is also written to the run's
summary page.
"""
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def main(argv):
    english = load(os.path.join(ROOT, "locales", "en.json"))
    rows = []
    missing_by_lang = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "locales", "*.json"))):
        lang = os.path.splitext(os.path.basename(path))[0]
        if lang == "en":
            continue
        have = load(path)
        missing = [s for s in english if s not in have]
        missing_by_lang[lang] = missing
        done = 100.0 * (len(english) - len(missing)) / len(english) if english else 100.0
        rows.append((lang, len(missing), done))
    total = len(english)
    print("{} sentences in English; still English in each language:".format(total))
    for lang, count, done in rows:
        print("  {:<6} {:>5} missing  ({:5.1f}% translated)".format(lang, count, done))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### Translations\n\n{} sentences in English.\n\n| Language | Missing | Translated |\n"
                     "|---|---:|---:|\n".format(total))
            for lang, count, done in rows:
                fh.write("| {} | {} | {:.1f}% |\n".format(lang, count, done))
    for lang in argv:
        print("\n--- missing in {} ---".format(lang))
        for sentence in missing_by_lang.get(lang, []):
            print(repr(sentence))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
