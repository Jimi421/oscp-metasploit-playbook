#!/bin/bash

#############################################
# Setup Script for OSCP Automation Toolkit
# Verifies dependencies and configures environment
# Author: Braxton
#############################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "================================================"
echo "  OSCP Automation Toolkit - Setup"
echo "================================================"
echo -e "${NC}"

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}[!] This toolkit is designed for Linux systems${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Checking dependencies...${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
MISSING_DEPS=0

# Check nmap
if command_exists nmap; then
    NMAP_VERSION=$(nmap --version | head -n1)
    echo -e "${GREEN}[+] nmap: ${NC}$NMAP_VERSION"
else
    echo -e "${RED}[!] nmap: Not found${NC}"
    MISSING_DEPS=$((MISSING_DEPS + 1))
fi

# Check msfconsole
if command_exists msfconsole; then
    MSF_VERSION=$(msfconsole --version 2>/dev/null | head -n1)
    echo -e "${GREEN}[+] metasploit: ${NC}$MSF_VERSION"
else
    echo -e "${RED}[!] metasploit: Not found${NC}"
    MISSING_DEPS=$((MISSING_DEPS + 1))
fi

# Check ip command
if command_exists ip; then
    echo -e "${GREEN}[+] ip: ${NC}Available"
else
    echo -e "${RED}[!] ip: Not found${NC}"
    MISSING_DEPS=$((MISSING_DEPS + 1))
fi

# Check for sudo
if command_exists sudo; then
    echo -e "${GREEN}[+] sudo: ${NC}Available"
else
    echo -e "${RED}[!] sudo: Not found${NC}"
    MISSING_DEPS=$((MISSING_DEPS + 1))
fi

echo ""

# Check if eth0 exists
if ip link show eth0 >/dev/null 2>&1; then
    ETH0_STATUS=$(ip -br a show eth0 | awk '{print $2}')
    ETH0_IP=$(ip -br a show eth0 | awk '{print $3}' | cut -d'/' -f1)
    echo -e "${GREEN}[+] eth0: ${NC}$ETH0_STATUS ($ETH0_IP)"
else
    echo -e "${YELLOW}[!] eth0: Not found (you may need to modify scripts)${NC}"
    echo -e "${YELLOW}    Available interfaces:${NC}"
    ip -br a | grep -v lo
fi

echo ""

# Report results
if [ $MISSING_DEPS -eq 0 ]; then
    echo -e "${GREEN}[+] All dependencies satisfied!${NC}"
    echo ""
    
    # Make scripts executable
    echo -e "${YELLOW}[*] Making scripts executable...${NC}"
    chmod +x auto_recon.sh 2>/dev/null
    
    if [ -x "auto_recon.sh" ]; then
        echo -e "${GREEN}[+] auto_recon.sh is executable${NC}"
    fi
    
    # Check Metasploit database
    echo ""
    echo -e "${YELLOW}[*] Checking Metasploit database...${NC}"
    
    if systemctl is-active --quiet postgresql; then
        echo -e "${GREEN}[+] PostgreSQL is running${NC}"
    else
        echo -e "${YELLOW}[!] PostgreSQL is not running${NC}"
        echo -e "${YELLOW}    Start with: sudo systemctl start postgresql${NC}"
    fi
    
    # Test MSF database connection
    if msfconsole -q -x "db_status; exit" 2>&1 | grep -q "Connected"; then
        echo -e "${GREEN}[+] Metasploit database is connected${NC}"
    else
        echo -e "${YELLOW}[!] Metasploit database not initialized${NC}"
        echo -e "${YELLOW}    Initialize with: sudo msfdb init${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}================================================${NC}"
    echo -e "${GREEN}Setup Complete!${NC}"
    echo ""
    echo -e "Quick start:"
    echo -e "  ${BLUE}1.${NC} Run reconnaissance: ${GREEN}sudo ./auto_recon.sh${NC}"
    echo -e "  ${BLUE}2.${NC} Start Metasploit: ${GREEN}msfconsole -r setup_msf.rc${NC}"
    echo ""
    echo -e "For more information, see: ${BLUE}README.md${NC}"
    echo -e "${BLUE}================================================${NC}"
    
else
    echo -e "${RED}[!] Missing $MISSING_DEPS required dependenc(ies)${NC}"
    echo ""
    echo -e "${YELLOW}Install missing tools on Kali Linux:${NC}"
    echo -e "  sudo apt update"
    echo -e "  sudo apt install -y nmap metasploit-framework"
    echo ""
    exit 1
fi
