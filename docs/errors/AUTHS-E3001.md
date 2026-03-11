# AUTHS-E3001: Key Not Found

The requested key alias does not exist in the keychain.

## Resolution

1. List available keys:
   ```bash
   auths key list
   ```
2. If the key was deleted, import from a backup:
   ```bash
   auths key import --alias <ALIAS> --file <BACKUP_PATH>
   ```
3. Or create a new key:
   ```bash
   auths init
   ```
