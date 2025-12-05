#!/bin/bash

#############################################
# Auto Recon Script for OSCP
# Performs network discovery and comprehensive scanning
# Author: Braxton
# Usage: ./auto_recon.sh
#############################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "================================================"
echo "    Auto Recon - OSCP Automation Tool"
echo "================================================"
echo -e "${NC}"

# Check if running as root for nmap
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] This script requires sudo privileges for nmap scanning${NC}"
    echo -e "${YELLOW}[*] Attempting to re-run with sudo...${NC}"
    sudo "$0" "$@"
    exit $?
fi

# Get eth0 IP address
echo -e "${YELLOW}[*] Detecting eth0 IP address...${NC}"
ETH0_IP=$(ip -br a show eth0 | awk '{print $3}' | cut -d'/' -f1)

if [ -z "$ETH0_IP" ]; then
    echo -e "${RED}[!] Could not detect eth0 IP address${NC}"
    echo -e "${YELLOW}[*] Available interfaces:${NC}"
    ip -br a
    exit 1
fi

echo -e "${GREEN}[+] eth0 IP: $ETH0_IP${NC}"

# Calculate network range
NETWORK=$(echo $ETH0_IP | cut -d'.' -f1-3).0/24
echo -e "${GREEN}[+] Target network: $NETWORK${NC}"

# Create timestamp for output files
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="."
PING_SWEEP="${OUTPUT_DIR}/ping_sweep_${TIMESTAMP}"
FULL_SCAN="${OUTPUT_DIR}/full_scan_${TIMESTAMP}"

# Step 1: Ping Sweep
echo -e "${YELLOW}[*] Starting ping sweep on $NETWORK...${NC}"
sudo nmap -sn $NETWORK -oA "$PING_SWEEP" --min-rate 1000

# Parse live hosts
echo -e "${YELLOW}[*] Parsing live hosts...${NC}"
LIVE_HOSTS=$(grep "Up" "${PING_SWEEP}.gnmap" | cut -d' ' -f2)
HOST_COUNT=$(echo "$LIVE_HOSTS" | wc -l)

if [ -z "$LIVE_HOSTS" ]; then
    echo -e "${RED}[!] No live hosts found${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Found $HOST_COUNT live host(s):${NC}"
echo "$LIVE_HOSTS" | while read host; do
    echo -e "    ${GREEN}→${NC} $host"
done

# Step 2: Full Comprehensive Scan
echo -e "${YELLOW}[*] Starting comprehensive scan on live hosts...${NC}"
echo -e "${YELLOW}[*] This may take a while...${NC}"

# Build target list
TARGET_LIST=$(echo "$LIVE_HOSTS" | tr '\n' ' ')

# Comprehensive scan with version detection, scripts, and OS detection
sudo nmap -sV -sC -O \
    --script=discovery,vuln \
    --script-args=unsafe=1 \
    -T4 \
    --min-rate 1000 \
    --max-retries 2 \
    -oA "$FULL_SCAN" \
    $TARGET_LIST

# Check if scan completed successfully
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Scan completed successfully!${NC}"
    echo -e "${GREEN}[+] Results saved to:${NC}"
    echo -e "    ${BLUE}→${NC} ${FULL_SCAN}.xml (XML format)"
    echo -e "    ${BLUE}→${NC} ${FULL_SCAN}.nmap (readable)"
    echo -e "    ${BLUE}→${NC} ${FULL_SCAN}.gnmap (greppable)"
else
    echo -e "${RED}[!] Scan encountered errors${NC}"
    exit 1
fi

# Summary
echo -e "${BLUE}"
echo "================================================"
echo "                 SCAN SUMMARY"
echo "================================================"
echo -e "${NC}"
echo -e "${GREEN}Network scanned:${NC} $NETWORK"
echo -e "${GREEN}Live hosts found:${NC} $HOST_COUNT"
echo -e "${GREEN}Your IP (eth0):${NC} $ETH0_IP"
echo -e "${GREEN}Scan output:${NC} ${FULL_SCAN}.*"
echo ""
echo -e "${YELLOW}[*] Next steps:${NC}"
echo -e "    1. Review scan results: ${BLUE}cat ${FULL_SCAN}.nmap${NC}"
echo -e "    2. Import to Metasploit: ${BLUE}msfconsole -r setup_msf.rc${NC}"
echo -e "    3. Start exploitation!"
echo ""
echo -e "${BLUE}================================================${NC}"
