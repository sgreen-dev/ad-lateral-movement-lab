#!/usr/bin/env python3
"""
generate_translations.py

Regenerates the SPL (detections/splunk/*.conf) and KQL (detections/kql/*.kql)
translations from the authoritative Sigma rules in detections/sigma/*.yml.

Sigma is the source of truth; these outputs are derived. CI runs this and then
`git diff --exit-code` to guarantee the committed translations match the rules.

Correlation rules (those with a top-level `correlation:` block) are converted
with their referenced base rules in scope, and only to SPL: the Kusto backend
does not support correlation rules, so no .kql is emitted for them (each base
rule still gets its own standalone .kql).

Usage:
    python scripts/generate_translations.py            # write files
    python scripts/generate_translations.py --check     # exit 1 if any would change
"""
import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIGMA_DIR = ROOT / "detections" / "sigma"
SPLUNK_DIR = ROOT / "detections" / "splunk"
KQL_DIR = ROOT / "detections" / "kql"


def sigma_bin() -> str:
    exe = shutil.which("sigma")
    if not exe:
        sys.exit("error: `sigma` CLI not found on PATH (pip install sigma-cli)")
    return exe


def name_index() -> dict:
    """Map each rule's `name:` field to its file path (for correlation refs)."""
    idx = {}
    for p in SIGMA_DIR.glob("*.yml"):
        doc = yaml.safe_load(p.read_text())
        if isinstance(doc, dict) and doc.get("name"):
            idx[doc["name"]] = p
    return idx


def convert(sigma: str, inputs: list, target: str, extra: list) -> str:
    proc = subprocess.run(
        [sigma, "convert", "-t", target, *extra, *[str(i) for i in inputs]],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        joined = ", ".join(i.name for i in inputs)
        sys.exit(f"error: converting {joined} -> {target} failed:\n{proc.stderr}")
    lines = [l for l in proc.stdout.splitlines() if l.strip() and "Parsing Sigma" not in l]
    return "\n".join(lines).strip()


def render(rule: pathlib.Path, doc: dict, query: str) -> str:
    header = (
        f"# GENERATED from {rule.relative_to(ROOT).as_posix()} by "
        f"scripts/generate_translations.py -- do not edit by hand.\n"
        f"# Rule: {doc['title']}\n"
        f"# Sigma id: {doc['id']}\n"
    )
    return header + query + "\n"


def outputs_for(rule: pathlib.Path, doc: dict, sigma: str, names: dict) -> dict:
    """Return {output_path: content} for a single rule file."""
    result = {}
    if "correlation" in doc:
        # Correlation: SPL only. The base rules it references must be resolved in
        # a single rule collection, which sigma-cli only does for a *directory*
        # input (multiple file args are treated as independent collections), so
        # convert a temp dir holding just the correlation rule + its base rules.
        base_names = doc["correlation"].get("rules", [])
        missing = [n for n in base_names if n not in names]
        if missing:
            sys.exit(f"error: {rule.name} references unknown rule name(s): {missing}")
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            for src in [rule] + [names[n] for n in base_names]:
                shutil.copy(src, tmp / src.name)
            spl = convert(sigma, [tmp], "splunk", ["-p", "sysmon"])
        result[SPLUNK_DIR / (rule.stem + ".conf")] = render(rule, doc, spl)
    else:
        spl = convert(sigma, [rule], "splunk", ["-p", "sysmon"])
        kql = convert(sigma, [rule], "kusto", [])
        result[SPLUNK_DIR / (rule.stem + ".conf")] = render(rule, doc, spl)
        result[KQL_DIR / (rule.stem + ".kql")] = render(rule, doc, kql)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if any file is stale")
    args = ap.parse_args()

    sigma = sigma_bin()
    SPLUNK_DIR.mkdir(parents=True, exist_ok=True)
    KQL_DIR.mkdir(parents=True, exist_ok=True)
    names = name_index()

    stale = []
    for rule in sorted(SIGMA_DIR.glob("*.yml")):
        doc = yaml.safe_load(rule.read_text())
        for out, content in outputs_for(rule, doc, sigma, names).items():
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
