# HarborGuard Coral Sources

This directory contains Coral source specs that HarborGuard needs but that may
not be bundled in the currently installed Coral CLI release.

Install them into the same Coral config used by HarborGuard's `.env`:

```powershell
$env:CORAL_CONFIG_DIR = "$env:APPDATA\withcoral\harborguard-config"
New-Item -ItemType Directory -Force $env:CORAL_CONFIG_DIR | Out-Null
$osv_manifest = (Resolve-Path .\coral-sources\community\osv\manifest.yaml).Path
$deps_dev_manifest = (Resolve-Path .\coral-sources\community\deps_dev\manifest.yaml).Path
.\coral\coral.exe source lint $osv_manifest
.\coral\coral.exe source add --file $osv_manifest
.\coral\coral.exe source add --file $deps_dev_manifest
.\coral\coral.exe source test osv
.\coral\coral.exe source test deps_dev
```

If you change `CORAL_CONFIG_DIR` in `.env`, install and list sources with that
same environment variable set before starting HarborGuard.

Then confirm Coral can see the source:

```powershell
.\coral\coral.exe sql --format json "SELECT schema_name, table_name FROM coral.tables WHERE schema_name IN ('osv', 'deps_dev') ORDER BY schema_name, table_name"
```

These source specs are copied from the Coral repository and are covered by the
Coral license included here as `LICENSE-CORAL`.

The `deps_dev` source is vendored from approved Coral PR 799:
https://github.com/withcoral/coral/pull/799
