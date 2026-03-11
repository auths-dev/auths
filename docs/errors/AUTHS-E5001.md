# AUTHS-E5001: Setup — No Identity Found

No Auths identity was found during setup. An identity must exist before this operation can proceed.

## Resolution

1. Create a new identity:
   ```bash
   auths init
   ```
2. Or import an existing identity from a backup:
   ```bash
   auths key import --alias <ALIAS> --file <BACKUP_PATH>
   ```
