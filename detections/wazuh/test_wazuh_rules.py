#!/usr/bin/env python3
"""
Offline validator for the native Wazuh rules in local_rules.xml.

WHAT THIS PROVES (and what it does not):
  * For every base rule it evaluates the rule's <field> conditions against a
    positive fixture (must MATCH) and a negative fixture (must NOT match) — i.e.
    a true-positive and a true-negative per rule. That is the discriminating
    logic of each detection: does it catch the attack event and stay silent on
    the benign look-alike?
  * It does NOT re-implement the full Wazuh engine. Structural preconditions
    (<if_group>, <decoded_as>, <if_sid>) and the temporal <if_matched_sid>
    correlation are validated LIVE with wazuh-logtest / a re-run of the atomic
    (see README). The correlation rule (100260) gets a structural check only.

Field matching mirrors Wazuh's PCRE2 <field> behaviour: unanchored search,
case sensitivity controlled by inline (?i) in the pattern, `negate="yes"`
inverts the result. Patterns here are PCRE2-compatible with Python `re`.

Run:  python detections/wazuh/test_wazuh_rules.py
Exit: 0 = all fixtures behaved as expected, 1 = at least one mismatch.
Also importable by pytest (functions prefixed test_).
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES_XML = HERE / "local_rules.xml"
EVIDENCE = HERE / "evidence"


# --- rule model -------------------------------------------------------------

def load_rules(path: Path = RULES_XML) -> dict[str, dict]:
    """Parse local_rules.xml into {rule_id: {fields, if_sid, if_matched_sid, same_field}}."""
    root = ET.parse(path).getroot()
    rules: dict[str, dict] = {}
    for rule in root.iter("rule"):
        rid = rule.get("id")
        fields = []
        for f in rule.findall("field"):
            fields.append(
                {
                    "name": f.get("name"),
                    "pattern": (f.text or "").strip(),
                    "negate": (f.get("negate") == "yes"),
                }
            )
        rules[rid] = {
            "level": rule.get("level"),
            "fields": fields,
            "if_sid": [e.text.strip() for e in rule.findall("if_sid")],
            "if_matched_sid": [e.text.strip() for e in rule.findall("if_matched_sid")],
            "same_field": [e.text.strip() for e in rule.findall("same_field")],
        }
    return rules


# --- field evaluation -------------------------------------------------------

def resolve_field(event: dict, name: str):
    """Resolve a Wazuh rule field ('win.eventdata.parentImage') against a decoded
    alert fixture, which nests the same path under 'data'."""
    for candidate in (name, f"data.{name}"):
        node = event
        ok = True
        for part in candidate.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                ok = False
                break
        if ok and not isinstance(node, (dict, list)):
            return node
    return None


def field_matches(field: dict, event: dict) -> bool:
    value = resolve_field(event, field["name"])
    hit = value is not None and re.search(field["pattern"], str(value)) is not None
    return (not hit) if field["negate"] else hit


def rule_matches(rule: dict, event: dict) -> bool:
    """A rule's field block matches iff every <field> condition is satisfied (AND)."""
    return all(field_matches(f, event) for f in rule["fields"])


# --- fixture-driven checks --------------------------------------------------

def iter_fixtures():
    for fx in sorted(EVIDENCE.glob("*.json")):
        doc = json.loads(fx.read_text(encoding="utf-8"))
        exp = doc.get("_expect")
        if not exp:  # a fixture without _expect is documentation only
            continue
        yield fx.name, exp["rule_id"], bool(exp["match"]), doc


def evaluate() -> list[dict]:
    rules = load_rules()
    results = []
    for name, rid, expected, doc in iter_fixtures():
        rule = rules.get(rid)
        if rule is None:
            results.append({"fixture": name, "ok": False, "why": f"rule {rid} not found in local_rules.xml"})
            continue
        actual = rule_matches(rule, doc)
        results.append(
            {
                "fixture": name,
                "rule": rid,
                "expected": expected,
                "actual": actual,
                "ok": actual == expected,
                "why": "" if actual == expected else f"expected match={expected}, got {actual}",
            }
        )
    return results


# --- pytest entry points ----------------------------------------------------

def test_all_fixtures_behave_as_expected():
    failures = [r for r in evaluate() if not r["ok"]]
    assert not failures, "fixture mismatches: " + "; ".join(f"{r['fixture']}: {r['why']}" for r in failures)


def test_correlation_rule_is_wired():
    """100260 must chain the PowerShell rule and require the WinRM rule on the same host."""
    r = load_rules().get("100260")
    assert r is not None, "correlation rule 100260 missing"
    assert "100250" in r["if_sid"], "100260 must <if_sid>100250</if_sid> (current event = suspicious PowerShell)"
    assert "100210" in r["if_matched_sid"], "100260 must <if_matched_sid>100210</if_matched_sid> (WinRM matched recently)"
    assert "win.system.computer" in r["same_field"], "100260 must correlate on <same_field>win.system.computer</same_field>"


def test_every_base_rule_has_both_fixtures():
    """Each base rule (not the correlation rule) needs a TP and a TN fixture."""
    seen: dict[str, set[bool]] = {}
    for _, rid, expected, _ in iter_fixtures():
        seen.setdefault(rid, set()).add(expected)
    base_rules = [rid for rid in load_rules() if rid != "100260"]
    missing = {rid: ({True, False} - seen.get(rid, set())) for rid in base_rules}
    missing = {rid: need for rid, need in missing.items() if need}
    assert not missing, f"rules missing TP/TN coverage: {missing}"


# --- CLI --------------------------------------------------------------------

def main() -> int:
    results = evaluate()
    width = max(len(r["fixture"]) for r in results)
    print(f"Wazuh rule validation - {RULES_XML.relative_to(HERE.parent.parent)}\n")
    for r in results:
        tag = "PASS" if r["ok"] else "FAIL"
        detail = f" rule {r.get('rule','?')} expect={r.get('expected')} got={r.get('actual')}"
        print(f"  [{tag}] {r['fixture']:<{width}}{detail}" + (f"  <- {r['why']}" if not r["ok"] else ""))

    passed = sum(r["ok"] for r in results)
    print(f"\n  {passed}/{len(results)} fixtures behaved as expected")

    # structural checks
    struct_fail = []
    for fn in (test_correlation_rule_is_wired, test_every_base_rule_has_both_fixtures):
        try:
            fn()
            print(f"  [PASS] {fn.__name__}")
        except AssertionError as e:
            struct_fail.append(str(e))
            print(f"  [FAIL] {fn.__name__}: {e}")

    return 0 if passed == len(results) and not struct_fail else 1


if __name__ == "__main__":
    sys.exit(main())
