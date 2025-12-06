#!/bin/bash
# Thin wrapper to keep SMB setup aligned with the repository-wide script.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "[SMB] Delegating to canonical setup script at ${ROOT_DIR}/setup.sh"
exec "${ROOT_DIR}/setup.sh" "$@"
