# Detections

Sigma rules + per-SIEM translations + test fixtures.

## Layout

| Path | Contents |
|---|---|
| [`sigma/`](sigma/) | Authoritative rules in Sigma format |
| [`splunk/`](splunk/) | SPL translations (one .conf per rule) |
| [`kql/`](kql/) | KQL translations for Sentinel/Defender |
| [`test_data/`](test_data/) | Sample events used to validate rules |

## Authoring conventions

1. **Sigma is source of truth.** SPL and KQL files are derived; never edit them by hand without also updating the Sigma source.
2. **Every rule has a real UUID.** Generate with `python -c "import uuid; print(uuid.uuid4())"`.
3. **Every rule cites its source.** If forked from SigmaHQ, link the original commit.
4. **Every rule lists at least one realistic false positive.** "None known" is a smell.
5. **Severity discipline:**
   - `low` — informational, dashboard-only
   - `medium` — analyst review during shift
   - `high` — page Tier 2 immediately
   - `critical` — page IR, multi-host implications

## Translation workflow

```bash
# Sigma → SPL
sigma convert -t splunk -p splunk_windows detections/sigma/T1021.001_*.yml

# Sigma → KQL (Sentinel)
sigma convert -t microsoft365defender detections/sigma/T1021.001_*.yml
```

CI lints the Sigma rules and (planned, Phase 4) regenerates the SPL/KQL on every commit.

## Status

| File | Status |
|---|---|
| `T1021.001_rdp_logon_unusual_source.yml` | Stub |
| `T1021.002_admin_share_access_anomalous.yml` | Stub |
| `T1021.006_winrm_execution.yml` | Stub |
| `T1059.001_powershell_post_winrm.yml` | Stub |
| `correlation_winrm_to_powershell.yml` | Stub |
