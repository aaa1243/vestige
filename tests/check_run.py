"""Checks a scan's JSON: no check crashed, and the expected findings are there.

usage: python tests/check_run.py report.json module:SEVERITY [module:SEVERITY ...]
       add "text" after a third colon to also require it in the title:
       game_modules:DETECTION:Injected program image
"""
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
findings = data["findings"]
got = sorted({(f["module"], f["severity"]) for f in findings})
print("findings:", got)
for n in data["notes"]:
    print("note:", n.splitlines()[0])
crashed = [n for n in data["notes"] if "failed" in n.split(":", 1)[-1][:12]]
if crashed:
    sys.exit("A check crashed: " + "; ".join(crashed))
missing = []
for want in sys.argv[2:]:
    parts = want.split(":", 2)
    module, severity = parts[0], parts[1]
    text = parts[2].lower() if len(parts) > 2 else ""
    if not any(f["module"] == module and f["severity"] == severity and text in f["title"].lower() for f in findings):
        missing.append(want)
if missing:
    sys.exit(f"Expected findings missing: {missing}")
print("OK")
