# HarborGuard Coral Sources

This directory contains Coral source specs that HarborGuard needs but that may
not be bundled in the currently installed Coral CLI release.

Install them into an isolated HarborGuard Coral config:

```powershell
$env:CORAL_CONFIG_DIR = "$env:TEMP\coral-harborguard"
coral source add --file .\coral-sources\community\osv\manifest.yaml
coral source add --file .\coral-sources\community\deps_dev\manifest.yaml
coral source test osv
coral source test deps_dev
```

Then confirm Coral can see the source:

```powershell
coral sql --format json "SELECT schema_name, table_name FROM coral.tables WHERE schema_name IN ('osv', 'deps_dev') ORDER BY schema_name, table_name"
```

These source specs are copied from the Coral repository and are covered by the
Coral license included here as `LICENSE-CORAL`.

The `deps_dev` source is vendored from approved Coral PR 799:
https://github.com/withcoral/coral/pull/799
