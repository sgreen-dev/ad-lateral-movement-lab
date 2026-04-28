"""
sysmon_ioc_extractor.py

Parses Sysmon events (JSON, as exported from Wazuh or Splunk) and emits a
clean IOC table for inclusion in incident reports.

Inputs:  one or more JSON files containing Sysmon events
Outputs: Markdown table (default) or STIX 2.1 bundle (--stix)

Populated in Phase 5.

Usage (planned):
    python sysmon_ioc_extractor.py events.json
    python sysmon_ioc_extractor.py events.json --stix > iocs.json
    cat events.json | python sysmon_ioc_extractor.py -
"""

# TODO Phase 5:
# - argparse: positional 'inputs' (list of files or '-'), --format {md,stix}
# - parse Sysmon EID 1 (process), 3 (network), 11 (file create), 22 (DNS)
# - dedupe by (event_type, key_field)
# - emit table with columns: Type | Value | First seen | Source EID | Host
# - --stix mode: emit STIX 2.1 indicator objects (file:hashes, ipv4-addr,
#   process, domain-name) in a bundle

if __name__ == "__main__":
    print("sysmon_ioc_extractor stub — populated in Phase 5")
