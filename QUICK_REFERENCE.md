# OSCP Quick Reference - Auto Recon Workflow

## 🚀 Workflow Commands

### 1. Initial Setup (First Time Only)
```bash
git clone https://github.com/yourusername/oscp-automation-toolkit.git
cd oscp-automation-toolkit
./setup.sh
```

### 2. Standard Recon Workflow
```bash
# Run automated recon
sudo ./auto_recon.sh

# Review results
cat full_scan_*.nmap | less

# Start Metasploit with data
msfconsole -r setup_msf.rc
```

---

## 📊 Metasploit Commands

### Database Management
```bash
# View all hosts
hosts

# View services on specific host
services <ip>

# Filter by port
services -p 445,139,22,80,443

# Add notes to host
hosts -h <ip> -n "Windows Server 2019 - Likely vulnerable to X"

# Search exploits
search type:exploit platform:windows
search smb
search type:auxiliary name:scanner
```

### Workspace Management
```bash
# List workspaces
workspace

# Create new workspace
workspace -a exam_box1

# Switch workspace  
workspace exam_box1

# Delete workspace
workspace -d old_workspace
```

### Additional Scanning from MSF
```bash
# Run nmap with database integration
db_nmap -sV -p- <target>

# SMB enumeration
use auxiliary/scanner/smb/smb_version
set RHOSTS <target>
run

# Check for EternalBlue
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS <target>
run
```

---

## 🔍 Manual Nmap Commands

### Quick Scans
```bash
# Fast top 1000 ports
nmap -T4 --top-ports 1000 <target>

# Full TCP scan
nmap -p- -T4 <target>

# UDP scan (top 100)
nmap -sU --top-ports 100 <target>

# Quick vulnerability scan
nmap --script vuln <target>
```

### Service Enumeration
```bash
# SMB enumeration
nmap -p 445 --script=smb-enum-shares,smb-enum-users <target>

# HTTP enumeration
nmap -p 80,443 --script=http-enum,http-methods <target>

# SNMP enumeration
nmap -sU -p 161 --script=snmp-* <target>

# FTP enumeration
nmap -p 21 --script=ftp-anon,ftp-bounce <target>
```

### Script Categories
```bash
# All discovery scripts
nmap --script=discovery <target>

# All vulnerability scripts
nmap --script=vuln <target>

# Specific script
nmap --script=<script-name> <target>

# Multiple scripts
nmap --script=http-enum,http-headers,http-methods <target>
```

---

## 🎯 Port-Specific Recon

### FTP (21)
```bash
nmap -p 21 --script=ftp-* <target>
ftp <target>  # Try anonymous:anonymous
```

### SSH (22)
```bash
nmap -p 22 --script=ssh-* <target>
ssh user@<target>
```

### Telnet (23)
```bash
nmap -p 23 --script=telnet-* <target>
telnet <target>
```

### SMTP (25)
```bash
nmap -p 25 --script=smtp-* <target>
telnet <target> 25
> VRFY root
> EXPN root
```

### DNS (53)
```bash
nmap -p 53 --script=dns-* <target>
dig @<target> domain.com ANY
```

### HTTP/HTTPS (80/443)
```bash
nmap -p 80,443 --script=http-* <target>
nikto -h http://<target>
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt
```

### POP3 (110)
```bash
nmap -p 110 --script=pop3-* <target>
telnet <target> 110
```

### RPC (111)
```bash
nmap -p 111 --script=rpc-* <target>
rpcinfo -p <target>
```

### NetBIOS (139)
```bash
nmap -p 139 --script=smb-* <target>
nbtscan <target>
```

### IMAP (143)
```bash
nmap -p 143 --script=imap-* <target>
telnet <target> 143
```

### SNMP (161)
```bash
nmap -sU -p 161 --script=snmp-* <target>
snmpwalk -v2c -c public <target>
onesixtyone -c community.txt <target>
```

### LDAP (389)
```bash
nmap -p 389 --script=ldap-* <target>
ldapsearch -x -h <target> -s base
```

### SMB (445)
```bash
nmap -p 445 --script=smb-* <target>
smbclient -L //<target>/ -N
smbmap -H <target>
enum4linux -a <target>
```

### MSSQL (1433)
```bash
nmap -p 1433 --script=ms-sql-* <target>
```

### MySQL (3306)
```bash
nmap -p 3306 --script=mysql-* <target>
mysql -h <target> -u root -p
```

### RDP (3389)
```bash
nmap -p 3389 --script=rdp-* <target>
xfreerdp /u:user /p:pass /v:<target>
```

### PostgreSQL (5432)
```bash
nmap -p 5432 --script=pgsql-* <target>
psql -h <target> -U postgres
```

### VNC (5900)
```bash
nmap -p 5900 --script=vnc-* <target>
vncviewer <target>
```

### Proxy (8080)
```bash
nmap -p 8080 --script=http-* <target>
```

---

## 💡 Pro Tips

### During Exam
1. Run `auto_recon.sh` immediately on new box
2. Review scan results while nmap runs
3. Keep notes in Metasploit database
4. Export workspace before switching boxes: `db_export -f xml backup.xml`
5. Take screenshots of everything important

### Time Savers
- Use aliases: `alias msfstart='msfconsole -r setup_msf.rc'`
- Keep a note template for each box
- Run UDP scan in background while working on TCP
- Always check for anonymous/guest access first
- Google the version numbers immediately

### Common Mistakes to Avoid
- Don't forget UDP scanning
- Always try default credentials
- Check for hidden directories/files
- Look for version numbers in banners
- Test all found credentials on all services

### Output Management
```bash
# Create organized directory structure
mkdir -p ~/oscp/{scans,exploits,loot,notes}

# Move scan results
mv full_scan_* ~/oscp/scans/box1/

# Keep organized notes
vim ~/oscp/notes/box1.md
```

---

## 🔐 Common Default Credentials

```
admin:admin
admin:password
administrator:administrator
root:root
root:toor
guest:guest
user:user
test:test
```

---

## 📝 Report Template

```markdown
# Box Name/IP: <target>

## Summary
- OS: 
- Difficulty: 
- Flags: User - X, Root - Y

## Enumeration
- Open Ports:
- Services:
- Web Directories:

## Exploitation
### User Access
- Method:
- Exploit Used:
- Steps:

### Privilege Escalation
- Method:
- Exploit Used:
- Steps:

## Flags
- User: 
- Root:

## Lessons Learned
-
```

---

## 🎓 Resources

- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.xyz/
- Reverse Shell Generator: https://www.revshells.com/
- CyberChef: https://gchq.github.io/CyberChef/

---

**Remember: Try Harder! 💪**
