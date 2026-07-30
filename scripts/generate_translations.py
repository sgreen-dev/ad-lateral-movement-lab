#!/usr/bin/env python3
"""
generate_translations.py

Regenerates the SPL (detections/splunk/*.conf) and KQL (detections/kql/*.kql)
translations from the authoritative Sigma rules in detections/sigma/*.yml.

Sigma is the source of truth; these outputs are derived. CI runs this and then
`git diff --exit-code` to guarantee the committed translations match the rules.

Usage:
    python scripts/generate_translations.py            # write files
    python scripts/generate_translations.py --check     # exit 1 if any would change
"""
import argparse
import pathlib
import shutil
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIGMA_DIR = ROOT / "detections" / "sigma"
SPLUNK_DIR = ROOT / "detections" / "splunk"
KQL_DIR = ROOT / "detections" / "kql"

# (target, backend-specific extra args, output dir, extension)
TARGETS = [
    ("splunk", ["-p", "sysmon"], SPLUNK_DIR, ".conf"),
    ("kusto", [], KQL_DIR, ".kql"),
]


def sigma_bin() -> str:
    exe = shutil.which("sigma")
    if not exe:
        sys.exit("error: `sigma` CLI not found on PATH (pip install sigma-cli)")
    return exe


def convert(sigma: str, rule: pathlib.Path, target: str, extra: list[str]) -> str:
    proc = subprocess.run(
        [sigma, "convert", "-t", target, *extra, str(rule)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.exit(f"error: converting {rule.name} -> {target} failed:\n{proc.stderr}")
    lines = [l for l in proc.stdout.splitlines() if l.strip() and "Parsing Sigma" not in l]
    return "\n".join(lines).strip()


def render(rule: pathlib.Path, query: str) -> str:
    doc = yaml.safe_load(rule.read_text())
    header = (
        f"# GENERATED from {rule.relative_to(ROOT).as_posix()} by "
        f"scripts/generate_translations.py -- do not edit by hand.\n"
        f"# Rule: {doc['title']}\n"
        f"# Sigma id: {doc['id']}\n"
    )
    return header + query + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if any file is stale")
    args = ap.parse_args()

    sigma = sigma_bin()
    SPLUNK_DIR.mkdir(parents=True, exist_ok=True)
    KQL_DIR.mkdir(parents=True, exist_ok=True)

    stale = []
    for rule in sorted(SIGMA_DIR.glob("*.yml")):
        for target, extra, out_dir, ext in TARGETS:
            content = render(rule, convert(sigma, rule, target, extra))
            out = out_dir / (rule.stem + ext)
            if args.check:
                current = out.read_text() if out.exists() else ""
                if current != content:
                    stale.append(out.relative_to(ROOT).as_posix())
            else:
                out.write_text(content)
                print(f"  wrote {out.relative_to(ROOT).as_posix()}")

    if args.check and stale:
        print("error: translations are out of date; run "
              "`python scripts/generate_translations.py`:", file=sys.stderr)
        for f in stale:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
