#!/usr/bin/env python3
"""
generate_attack_layer.py

Builds an ATT&CK Navigator layer (docs/attack-navigator-layer.json) from the
`attack.tXXXX[.YYY]` tags on the Sigma rules in detections/sigma/*.yml, so the
coverage map stays derived from the rules rather than hand-maintained.

Usage:
    python scripts/generate_attack_layer.py            # write the layer JSON
    python scripts/generate_attack_layer.py --check     # exit 1 if it is stale
"""
import argparse
import json
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIGMA_DIR = ROOT / "detections" / "sigma"
LAYER = ROOT / "docs" / "attack-navigator-layer.json"

# attack.t1021.002 -> T1021.002 ; attack.t1059.001 -> T1059.001
TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def collect() -> dict:
    """Map technique ID -> sorted list of rule titles that cover it."""
    coverage: dict[str, set] = {}
    for p in sorted(SIGMA_DIR.glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        title = doc.get("title", p.name)
        for tag in doc.get("tags", []) or []:
            m = TECH_RE.match(str(tag))
            if m:
                tid = m.group(1).upper()
                coverage.setdefault(tid, set()).add(title)
    return {tid: sorted(titles) for tid, titles in sorted(coverage.items())}


def build_layer(coverage: dict) -> dict:
    techniques = [
        {
            "techniqueID": tid,
            "score": 100,
            "enabled": True,
            "comment": "Detected by: " + "; ".join(titles),
            "metadata": [{"name": "rules", "value": str(len(titles))}],
        }
        for tid, titles in coverage.items()
    ]
    return {
        "name": "AD Lateral Movement Lab - Detection Coverage",
        "versions": {"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Techniques with authored Sigma detections in this lab. Generated "
            "from rule tags by scripts/generate_attack_layer.py."
        ),
        "sorting": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [{"label": "Detection authored", "color": "#0d4a90"}],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the layer is stale")
    args = ap.parse_args()

    content = json.dumps(build_layer(collect()), indent=2) + "\n"
    if args.check:
        current = LAYER.read_text() if LAYER.exists() else ""
        if current != content:
            print("error: ATT&CK layer is stale; run "
                  "`python scripts/generate_attack_layer.py`", file=sys.stderr)
            return 1
        return 0
    LAYER.parent.mkdir(parents=True, exist_ok=True)
    LAYER.write_text(content)
    print(f"  wrote {LAYER.relative_to(ROOT).as_posix()} "
          f"({len(collect())} techniques)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
