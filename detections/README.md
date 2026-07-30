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

SPL and KQL files are generated from the Sigma source by a single script — never
hand-edit `splunk/` or `kql/`:

```bash
# Regenerate all translations from detections/sigma/*.yml
python scripts/generate_translations.py

# Or convert one rule ad hoc:
sigma convert -t splunk -p sysmon detections/sigma/T1021.001_*.yml   # -> SPL
sigma convert -t kusto              detections/sigma/T1021.001_*.yml   # -> KQL
```

CI lints the Sigma rules and runs `generate_translations.py --check` on every
commit — the build fails if any rule stops converting or if a committed
translation drifts from its Sigma source.

## Status

| File | Status |
|---|---|
| `T1021.002_admin_share_access_anomalous.yml` | Finalized (`test`) |
| `T1021_002_smb_lateral_movement.yml` | Finalized (`experimental`) |
| `T1021.001_rdp_logon_unusual_source.yml` | Finalized (`test`) |
| `T1021.006_winrm_execution.yml` | Finalized (`test`) |
| `T1059.001_powershell_post_winrm.yml` | Finalized (`test`) |
| `correlation_winrm_to_powershell.yml` | Planned (Phase 4 — correlation backend) |
