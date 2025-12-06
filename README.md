# OSCP Metasploit Playbook

A collection of automation scripts to streamline reconnaissance and exploitation workflows for OSCP preparation and penetration testing.

## 🎯 Features

- **Automated Network Discovery**: Intelligent network scanning based on active interfaces
- **Comprehensive Reconnaissance**: Multi-stage nmap scanning with version detection and vulnerability scripts
- **Metasploit Integration**: Automatic workspace setup and scan data import
- **OSCP-Optimized**: Designed for efficiency in exam and lab environments

## 📋 Prerequisites

- Kali Linux (or similar pentest distribution)
- `nmap` installed
- `metasploit-framework` installed
- `sudo` privileges for network scanning
- Active `eth0` network interface

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/jimi421/oscp-metasploit-playbook.git
cd oscp-metasploit-playbook
chmod +x auto_recon.sh setup.sh setup/auto_nmap.sh
```

### 2. Run Setup Checks (First Time)

```bash
./setup.sh
```

The setup script verifies required tools (nmap, Metasploit, sudo, ip), checks network interfaces, and ensures scripts are executable.

### 3. Run Network Reconnaissance

```bash
sudo ./auto_recon.sh
```

This script will:
- Detect your eth0 IP address
- Perform a ping sweep on the /24 network
- Conduct comprehensive nmap scans on live hosts
- Save results in XML, nmap, and gnmap formats

### 4. Import to Metasploit

```bash
msfconsole -r setup_msf.rc
```

This resource script will:
- Create a timestamped workspace
- Import the latest scan results
- Configure LHOST automatically
- Display hosts and services

## 📁 File Structure

```
oscp-metasploit-playbook/
├── auto_recon.sh        # Main reconnaissance script
├── setup.sh             # Dependency checks and permissions
├── setup_msf.rc         # Metasploit resource script
├── protocols/           # Protocol-specific reference notes (http, smb, winrm)
├── setup/               # Supplemental setup helpers
│   └── auto_nmap.sh     # Metasploit-integrated nmap helper
├── PROJECT_SUMMARY.md   # Project overview
├── QUICK_REFERENCE.md   # One-page command reference
└── README.md            # This file
```

## 🔧 Script Details

### auto_recon.sh

**Scan Stages:**
1. **Ping Sweep**: Fast host discovery (`-sn`)
2. **Comprehensive Scan**: 
   - Version detection (`-sV`)
   - Default scripts (`-sC`)
   - OS detection (`-O`)
   - Discovery scripts (`--script=discovery`)
   - Vulnerability scripts (`--script=vuln`)

**Output Files:**
- `ping_sweep_YYYYMMDD_HHMMSS.*` - Initial host discovery
- `full_scan_YYYYMMDD_HHMMSS.*` - Complete scan results

**Nmap Timing:**
- Template: `-T4` (Aggressive)
- Min rate: `1000` packets/sec
- Max retries: `2`

### setup_msf.rc

**Features:**
- Automatic scan file detection (uses most recent)
- Dynamic LHOST configuration from eth0
- Workspace creation with timestamps
- Service filtering for common attack vectors
- Pre-configured global variables

## 💡 Usage Examples

### Basic Workflow

```bash
# 1. Run reconnaissance
sudo ./auto_recon.sh

# 2. Review results
cat full_scan_*.nmap

# 3. Start Metasploit with imported data
msfconsole -r setup_msf.rc

# 4. In Metasploit
msf6 > hosts
msf6 > services -p 445
msf6 > search smb
```

### Custom Nmap Scans

After initial recon, you can run targeted scans:

```bash
# SMB enumeration
sudo nmap -p 445 --script=smb-enum-* <target>

# Web service enumeration
sudo nmap -p 80,443 --script=http-enum,http-headers <target>

# Full port scan on specific host
sudo nmap -p- -T4 <target>
```

### Metasploit Workspace Management

```bash
# List workspaces
workspace

# Switch workspace
workspace <name>

# Delete workspace
workspace -d <name>

# Export data
db_export -f xml /path/to/export.xml
```

## ⚙️ Customization

### Modify Scan Timing

Edit `auto_recon.sh` line ~90:

```bash
# For stealth (slower)
-T2 --min-rate 100

# For speed (noisier)  
-T4 --min-rate 5000

# For exam (balanced)
-T3 --min-rate 1000
```

### Add Custom Nmap Scripts

Edit `auto_recon.sh` line ~85:

```bash
--script=discovery,vuln,exploit,http-enum,smb-enum-shares
```

### Change Metasploit Defaults

Edit `setup_msf.rc` lines ~48-49:

```ruby
setg LHOST %LHOST%
setg LPORT 4444  # Change to your preferred port
```

## 🐛 Troubleshooting

### "Could not detect eth0 IP address"

**Solution**: Check your interface name
```bash
ip -br a
# Use the correct interface name in the script
```

### "No scan files found"

**Solution**: Ensure `auto_recon.sh` completed successfully
```bash
ls -la full_scan_*.xml
```

### Nmap: "You do not have permission"

**Solution**: Run with sudo
```bash
sudo ./auto_recon.sh
```

### Metasploit: Database not connected

**Solution**: Start PostgreSQL and initialize MSF database
```bash
sudo systemctl start postgresql
sudo msfdb init
```

## 📝 Best Practices

1. **Always run recon first**: Complete `auto_recon.sh` before Metasploit
2. **Review scan results**: Check `.nmap` files before exploitation
3. **Use workspaces**: Keep different engagements separated
4. **Document findings**: Add notes to Metasploit database
5. **Clean up**: Remove old scan files and workspaces regularly

## 🎓 OSCP Tips

- Run initial recon as soon as you start a box
- Keep notes in Metasploit: `hosts -h <ip> -n "Windows 10, likely vulnerable to X"`
- Use `search` extensively: `search type:exploit platform:windows`
- Save successful exploits: `save` command in msfconsole
- Export data before logging off: `db_export`

## 🔐 Security Considerations

- **Only use on authorized systems**
- Aggressive scanning may trigger IDS/IPS
- Some scripts may cause service disruptions
- Always have explicit permission before scanning

## 📚 Additional Resources

- [OSCP Exam Guide](https://help.offensive-security.com/hc/en-us/articles/360040165632)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## 🤝 Contributing

Contributions welcome! Feel free to:
- Submit bug reports
- Propose new features
- Share improvements
- Add documentation

## 📄 License

MIT License - Feel free to use and modify for your OSCP journey!

## ⚠️ Disclaimer

This toolkit is for authorized security testing and OSCP lab/exam use only. Unauthorized scanning and exploitation of systems is illegal. Always obtain proper authorization before conducting security assessments.

---

**Good luck on your OSCP journey! 🎉**

*"Try Harder" - Offensive Security*
