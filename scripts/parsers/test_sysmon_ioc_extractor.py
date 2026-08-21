"""Tests for sysmon_ioc_extractor.

Runnable two ways:
    python -m pytest scripts/parsers/test_sysmon_ioc_extractor.py
    python scripts/parsers/test_sysmon_ioc_extractor.py     # no pytest needed
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sysmon_ioc_extractor as ie  # noqa: E402


def _sysmon(eid, **eventdata):
    ts = eventdata.pop("_ts", "2026-08-20T14:00:00.000Z")
    host = eventdata.pop("_host", "WIN01.lab.local")
    return {
        "timestamp": ts,
        "data": {"win": {
            "system": {
                "providerName": "Microsoft-Windows-Sysmon",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "eventID": str(eid),
                "computer": host,
                "systemTime": ts,
            },
            "eventdata": eventdata,
        }},
    }


def _types(iocs):
    return {i.type for i in iocs}


def _by_type(iocs, t):
    return [i for i in iocs if i.type == t]


# --- extraction -------------------------------------------------------------

def test_extracts_process_and_hash_iocs():
    ev = _sysmon(
        1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        commandLine="powershell.exe -EncodedCommand SQBFAFgA",
        hashes="SHA256=ABC123,MD5=DEF456,IMPHASH=IGNOREME",
    )
    iocs = ie.extract_iocs([ev])
    assert _types(iocs) == {"process", "sha256", "md5"}
    assert _by_type(iocs, "process")[0].value == "powershell.exe -EncodedCommand SQBFAFgA"
    assert _by_type(iocs, "sha256")[0].value == "ABC123"
    # IMPHASH / SHA1 are intentionally dropped
    assert not _by_type(iocs, "imphash")


def test_extracts_network_iocs():
    ev = _sysmon(3, destinationIp="10.0.1.10", destinationPort="80",
                 destinationHostname="staging.lab.test", image="powershell.exe")
    iocs = ie.extract_iocs([ev])
    assert _by_type(iocs, "ipv4-addr")[0].value == "10.0.1.10"
    assert _by_type(iocs, "domain-name")[0].value == "staging.lab.test"


def test_extracts_file_and_dns_iocs():
    file_ev = _sysmon(11, targetFilename="C:\\Users\\svc_backup\\AppData\\Local\\Temp\\update.ps1")
    dns_ev = _sysmon(22, queryName="c2.evil.test")
    iocs = ie.extract_iocs([file_ev, dns_ev])
    assert _by_type(iocs, "file-path")[0].value.endswith("update.ps1")
    assert _by_type(iocs, "domain-name")[0].value == "c2.evil.test"


def test_skips_non_sysmon_events():
    security_4624 = {"data": {"win": {
        "system": {"providerName": "Microsoft-Windows-Security-Auditing",
                   "channel": "Security", "eventID": "4624", "computer": "WIN01"},
        "eventdata": {"targetUserName": "svc_backup", "ipAddress": "10.0.2.10"},
    }}}
    powershell_4104 = {"data": {"win": {
        "system": {"providerName": "Microsoft-Windows-PowerShell",
                   "channel": "Microsoft-Windows-PowerShell/Operational",
                   "eventID": "4104", "computer": "WIN01"},
        "eventdata": {"scriptBlockText": "IEX(...)"},
    }}}
    assert ie.extract_iocs([security_4624, powershell_4104]) == []


def test_dedupes_by_type_and_value_keeping_earliest():
    early = _sysmon(3, destinationIp="10.0.1.10", _ts="2026-08-20T14:02:15.000Z")
    late = _sysmon(3, destinationIp="10.0.1.10", _ts="2026-08-20T14:05:59.000Z")
    iocs = ie.extract_iocs([late, early])
    ips = _by_type(iocs, "ipv4-addr")
    assert len(ips) == 1
    assert ips[0].first_seen == "2026-08-20T14:02:15.000Z"  # earliest wins


def test_handles_malformed_events_gracefully():
    junk = [None, "not-a-dict", 42, {}, {"data": {}}, {"data": {"win": {"system": {}}}}]
    assert ie.extract_iocs(junk) == []  # no crash, no IOCs


def test_load_events_accepts_array_object_and_ndjson():
    ev = _sysmon(3, destinationIp="10.0.1.10")
    assert len(ie.load_events(json.dumps([ev, ev]))) == 2
    assert len(ie.load_events(json.dumps(ev))) == 1
    assert len(ie.load_events(json.dumps(ev) + "\n" + json.dumps(ev))) == 2
    assert ie.load_events("") == []


# --- output -----------------------------------------------------------------

def test_markdown_table_has_header_and_rows():
    iocs = ie.extract_iocs([_sysmon(3, destinationIp="10.0.1.10")])
    md = ie.to_markdown(iocs)
    assert md.startswith("| Type | Value | First seen (UTC) | Source EID | Host |")
    assert "`10.0.1.10`" in md
    assert ie.to_markdown([]).endswith("| _none_ | | | | |")


def test_stix_output_is_valid_bundle():
    events = [
        _sysmon(1, image="powershell.exe", commandLine="powershell -enc AAAA",
                hashes="SHA256=ABC123,MD5=DEF456"),
        _sysmon(3, destinationIp="10.0.1.10"),
        _sysmon(11, targetFilename="C:\\Temp\\update.ps1"),
    ]
    bundle = ie.to_stix_bundle(ie.extract_iocs(events))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["objects"], "expected indicator objects"
    required = {"type", "spec_version", "id", "created", "modified", "pattern", "pattern_type", "valid_from"}
    for obj in bundle["objects"]:
        assert obj["type"] == "indicator"
        assert required <= set(obj), f"missing keys: {required - set(obj)}"
        assert obj["id"].startswith("indicator--")
        assert obj["pattern"].startswith("[") and obj["pattern"].endswith("]")
    # deterministic ids: same input -> same ids
    again = ie.to_stix_bundle(ie.extract_iocs(events))
    assert [o["id"] for o in bundle["objects"]] == [o["id"] for o in again["objects"]]


def test_stix_pattern_shapes():
    patterns = {i.type: ie._stix_pattern(i) for i in [
        ie.IOC("ipv4-addr", "10.0.1.10", "-", "3", "WIN01"),
        ie.IOC("sha256", "ABC", "-", "1", "WIN01"),
        ie.IOC("md5", "DEF", "-", "1", "WIN01"),
        ie.IOC("file-path", "C:\\Temp\\update.ps1", "-", "11", "WIN01"),
        ie.IOC("domain-name", "c2.evil.test", "-", "22", "WIN01"),
        ie.IOC("process", "powershell -enc AAAA", "-", "1", "WIN01"),
    ]}
    assert patterns["ipv4-addr"] == "[ipv4-addr:value = '10.0.1.10']"
    assert patterns["sha256"] == "[file:hashes.'SHA-256' = 'ABC']"
    assert patterns["md5"] == "[file:hashes.'MD5' = 'DEF']"
    assert patterns["file-path"] == "[file:name = 'update.ps1']"
    assert patterns["domain-name"] == "[domain-name:value = 'c2.evil.test']"
    assert patterns["process"].startswith("[process:command_line = ")


def test_end_to_end_on_committed_sample():
    """The shipped exemplar event set must yield the IOCs the incident report cites."""
    sample = Path(__file__).resolve().parents[2] / "attack-emulation" / "sample-events.winrm-to-powershell.json"
    iocs = ie.extract_iocs(ie.load_events(sample.read_text(encoding="utf-8")))
    types = _types(iocs)
    assert {"process", "sha256", "md5", "ipv4-addr", "file-path"} <= types
    assert any(i.value == "10.0.1.10" for i in _by_type(iocs, "ipv4-addr"))
    assert any(i.value.endswith("update.ps1") for i in _by_type(iocs, "file-path"))


# --- no-pytest runner -------------------------------------------------------

def _run_without_pytest() -> int:
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  [PASS] {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  [FAIL] {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  [ERROR] {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n  {len(fns) - failed}/{len(fns)} tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_without_pytest())
