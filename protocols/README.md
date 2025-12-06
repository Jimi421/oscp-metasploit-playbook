# Protocol-Specific Notes

All protocol folders share the repository-wide setup process. Run the canonical setup script from the repository root before using any protocol resources:

```bash
./setup.sh
```

If you are working inside a protocol directory and need to trigger setup checks, call the same script via a relative path:

```bash
../../setup.sh
```

Protocol wrappers (e.g., `smb/setup.sh`) simply delegate to this shared script so dependency checks stay consistent.
