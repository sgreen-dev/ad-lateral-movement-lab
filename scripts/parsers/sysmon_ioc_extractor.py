#!/usr/bin/env python3
"""
sysmon_ioc_extractor.py

Parses Sysmon events (JSON, as exported from Wazuh or Splunk) and emits a clean
IOC table for inclusion in incident reports, or a STIX 2.1 bundle.

Handles Sysmon:
    EID 1  process creation  -> process (image + command line), file hashes
    EID 3  network connect   -> ipv4-addr (dest), domain-name (dest hostname)
    EID 11 file create       -> file-path
    EID 22 DNS query         -> domain-name

Input event shape: Wazuh's decoded windows_eventchannel alert (fields under
`data.win.system.*` / `data.win.eventdata.*`) OR a already-flattened event
(top-level `EventID`, `Image`, ...). Non-Sysmon events (Security 4624,
PowerShell 4104, ...) are skipped. Input may be a JSON array, a single object,
or newline-delimited JSON; pass files or `-` for stdin.

Usage:
    python sysmon_ioc_extractor.py events.json
    python sysmon_ioc_extractor.py events.json --format stix > iocs.json
    cat events.json | python sysmon_ioc_extractor.py -

Exit code 0 on success (even with zero IOCs), 2 on bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Deterministic namespace so the same IOC always yields the same STIX id
# (no wall-clock / randomness — reproducible output).
_NS = uuid.UUID("6f2b9d7e-0000-4000-8000-ad1a7e120006")
_STIX_FALLBACK_TS = "2026-08-20T14:00:00.000Z"

SYSMON_EIDS = {"1", "3", "11", "22"}


@dataclass(frozen=True)
class IOC:
    type: str          # process | sha256 | md5 | ipv4-addr | domain-name | file-path
    value: str
    first_seen: str
    source_eid: str
    host: str


# --- field access -----------------------------------------------------------

def _get(event: dict, *names: str):
    """Fetch the first present field, checking the Wazuh nested path
    (data.win.system.*/data.win.eventdata.*) and a flat top-level key."""
    win = (event.get("data") or {}).get("win") or {}
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or {}
    for name in names:
        for source in (eventdata, system, event):
            if name in source and source[name] not in (None, ""):
                return source[name]
    return None


def _event_id(event: dict) -> str | None:
    v = _get(event, "eventID", "EventID")
    return str(v) if v is not None else None


def _is_sysmon(event: dict) -> bool:
    provider = str(_get(event, "providerName", "ProviderName") or "")
    channel = str(_get(event, "channel", "Channel") or "")
    return "Sysmon" in provider or "Sysmon" in channel


def _timestamp(event: dict) -> str:
    return str(_get(event, "systemTime", "SystemTime") or event.get("timestamp") or "-")


def _host(event: dict) -> str:
    return str(_get(event, "computer", "Computer", "Hostname") or "-")


# --- IOC extraction ---------------------------------------------------------

def _parse_hashes(raw: str) -> list[tuple[str, str]]:
    """'SHA256=AA..,MD5=BB..' -> [('sha256','AA..'), ('md5','BB..')]. Ignores
    algorithms we don't surface (IMPHASH, SHA1)."""
    keep = {"SHA256": "sha256", "MD5": "md5"}
    out = []
    for part in str(raw).split(","):
        if "=" in part:
            algo, _, val = part.partition("=")
            key = keep.get(algo.strip().upper())
            if key and val.strip():
                out.append((key, val.strip()))
    return out


def _iocs_from_event(event: dict) -> Iterable[IOC]:
    eid = _event_id(event)
    if eid not in SYSMON_EIDS or not _is_sysmon(event):
        return
    ts, host = _timestamp(event), _host(event)

    if eid == "1":
        image = _get(event, "image", "Image")
        cmdline = _get(event, "commandLine", "CommandLine")
        proc = cmdline or image
        if proc:
            yield IOC("process", str(proc), ts, eid, host)
        for algo, val in _parse_hashes(_get(event, "hashes", "Hashes") or ""):
            yield IOC(algo, val, ts, eid, host)

    elif eid == "3":
        dip = _get(event, "destinationIp", "DestinationIp")
        if dip:
            yield IOC("ipv4-addr", str(dip), ts, eid, host)
        dhost = _get(event, "destinationHostname", "DestinationHostname")
        if dhost:
            yield IOC("domain-name", str(dhost), ts, eid, host)

    elif eid == "11":
        target = _get(event, "targetFilename", "TargetFilename")
        if target:
            yield IOC("file-path", str(target), ts, eid, host)

    elif eid == "22":
        query = _get(event, "queryName", "QueryName")
        if query:
            yield IOC("domain-name", str(query), ts, eid, host)


def extract_iocs(events: Iterable[dict]) -> list[IOC]:
    """Extract and de-duplicate IOCs. Dedupe key is (type, value); the earliest
    first_seen wins so the table shows when an IOC was first observed."""
    best: dict[tuple[str, str], IOC] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        for ioc in _iocs_from_event(event):
            key = (ioc.type, ioc.value)
            prev = best.get(key)
            if prev is None or (ioc.first_seen < prev.first_seen):
                best[key] = ioc
    order = {"process": 0, "sha256": 1, "md5": 2, "ipv4-addr": 3, "domain-name": 4, "file-path": 5}
    return sorted(best.values(), key=lambda i: (order.get(i.type, 9), i.first_seen, i.value))


# --- input loading ----------------------------------------------------------

def load_events(text: str) -> list[dict]:
    """Parse a JSON array, a single object, or newline-delimited JSON."""
    text = text.strip()
    if not text:
        return []
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        if isinstance(doc, dict):
            # Wazuh sometimes wraps hits; otherwise treat as a single event
            return [doc]
    except json.JSONDecodeError:
        pass
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except json.JSONDecodeError:
            continue
    return events


def read_inputs(inputs: list[str]) -> list[dict]:
    events: list[dict] = []
    for path in inputs:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        events.extend(load_events(text))
    return events


# --- output -----------------------------------------------------------------

def to_markdown(iocs: list[IOC]) -> str:
    header = "| Type | Value | First seen (UTC) | Source EID | Host |\n|---|---|---|---|---|"
    if not iocs:
        return header + "\n| _none_ | | | | |"
    rows = [f"| {i.type} | `{i.value}` | {i.first_seen} | {i.source_eid} | {i.host} |" for i in iocs]
    return "\n".join([header, *rows])


def _stix_pattern(ioc: IOC) -> str:
    v = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
    if ioc.type == "ipv4-addr":
        return f"[ipv4-addr:value = '{v}']"
    if ioc.type == "domain-name":
        return f"[domain-name:value = '{v}']"
    if ioc.type == "sha256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    if ioc.type == "md5":
        return f"[file:hashes.'MD5' = '{v}']"
    if ioc.type == "file-path":
        name = ioc.value.replace("/", "\\").split("\\")[-1].replace("'", "\\'")
        return f"[file:name = '{name}']"
    return f"[process:command_line = '{v}']"


def to_stix_bundle(iocs: list[IOC]) -> dict[str, Any]:
    objects = []
    for ioc in iocs:
        pattern = _stix_pattern(ioc)
        oid = "indicator--" + str(uuid.uuid5(_NS, pattern))
        ts = ioc.first_seen if ioc.first_seen.endswith("Z") else _STIX_FALLBACK_TS
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": oid,
                "created": ts,
                "modified": ts,
                "name": f"{ioc.type}: {ioc.value}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ts,
            }
        )
    bundle_id = "bundle--" + str(uuid.uuid5(_NS, "||".join(o["id"] for o in objects)))
    return {"type": "bundle", "id": bundle_id, "objects": objects}


# --- CLI --------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract IOCs from Sysmon events (Wazuh/Splunk JSON).")
    ap.add_argument("inputs", nargs="+", help="event JSON file(s), or '-' for stdin")
    ap.add_argument("--format", choices=["md", "stix"], default="md", help="output format (default: md)")
    args = ap.parse_args(argv)

    try:
        events = read_inputs(args.inputs)
    except (OSError, ValueError) as e:
        print(f"error reading input: {e}", file=sys.stderr)
        return 2

    iocs = extract_iocs(events)
    if args.format == "stix":
        print(json.dumps(to_stix_bundle(iocs), indent=2))
    else:
        print(to_markdown(iocs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
