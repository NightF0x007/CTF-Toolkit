# Network Service and Port Enumeration

## Nmap:
General Scan
```sh
sudo nmap -p- -Pn -v -sCV -T4 --script vuln --max-retries 1 --min-rate 1000 $TARGET -oN nmap_out.txt
```
Host Discovery
```sh
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5 | tee hosts.lst
```
Scan Network Range
```sh
 sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

```sh
mkdir -p ./scans && sudo nmap -p- -Pn -v -sCV -T4 --min-rate 1000 -oA scans/nmap_out -iL hosts.lst && xsltproc scans/nmap_out.xml -o scans/nmap_out.html
```

HTML file of the XML output (`-oA nmap_out`)
```sh
xsltproc nmap_out.xml -o nmap_out.html
xsltproc -o nmap_out.html /usr/share/nmap/nmap.xsl nmap_out.xml
```
## Alternative Post Scans and Host Discovery 

```
printf "Normal \e[5m\e[31mBlink\e[0m\n"
```
- Incorporate the blinking

Ping Sweep For Loop on Linux Pivot Hosts
```sh
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

Netcat Port Scan
```sh
for i in {1..14}; for p in {1..9999}; do if timeout 1 bash -c "proxychains -q nc -vz 172.18.0.${i} ${p}" 2>/dev/null; then echo "HELL NAH! ===> 172.18.0.$i:$p found out! <====\r"\\r; else printf "Checking 172.18.0.$i on port $p"\\r; fi; done
```

```sh
for i in {1..14}; for p in $(cat nmap-ports-top1000.txt); do if timeout 1 bash -c "proxychains -q nc -vz 172.18.0.${i} ${p}" 2>/dev/null; then echo "HELL NAH! ===> 172.18.0.$i:$p found out! <====\n\r"\\r; else printf "Checking 172.18.0.$i on port $p"\\r; fi; done
```

- select with a list: `1 2 3 4` or `(1 1 4)`
- Another way to do a sequence of numbers: `$(seq 1 65535)`

Ping Sweep For Loop Using CMD
```sh
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```
Ping Sweep Using PowerShell
```sh
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"} | Select-String -Pattern True
```
Meterpreter Ping Sweep
```
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```
Openssl linux host discovery
```sh
for host in 1 2 3 4; do for port in 21 22 25 80 443 8080; do echo 172.19.0.$host:$port & openssl s_client -connect 172.19.0.$host:$port 2>/dev/null | grep CONNECTED; done; done
```
/dev/tcp Port Scan
```sh
for port in $(seq 1 65535); do (echo fox > /dev/tcp/172.19.0.2/$port && echo $port) 2>/dev/null; done
```
bash exec host and port scan
```sh
#!/usr/bin/env bash
set -u

NET_PREFIX="172.19.0"
HOSTS=(1 2 3 4)
TIMEOUT=1   # seconds

# for h in {1..254}; do # to iterate over entire /24 subnet uncomment this line
for h in "${HOSTS[@]}"; do # to iterate over a smaller list comment line above
  ip="${NET_PREFIX}.${h}"
  for p in $(seq 1 65535); do
    if timeout "${TIMEOUT}" bash -c "exec 3<>/dev/tcp/${ip}/${p}" 2>/dev/null; then
      echo "[OPEN] ${ip}:${p}"
      # Close FD 3 (best effort)
      timeout 0.1 bash -c "exec 3<&- 3>&-" 2>/dev/null || true
    else
      echo "[....] ${ip}:${p}"
    fi
  done
done
```

[Thank you Carlos Polop](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology)

# ASN Subdomain Enumeration

[BBOT](https://github.com/blacklanternsecurity/bbot)
Crawl www[.]evilcorp[.]com up to a max depth of 2, automatically extracting emails, secrets, etc.
```sh
bbot -t www.evilcorp.com -m httpx robots badsecrets secretsdb -c web_spider_distance=2 web_spider_depth=2
```

```sh
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

# DNS Enumeration

| **Command**                                         | **Description**                                                       |
| --------------------------------------------------- | --------------------------------------------------------------------- |
| `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb` | Perform an AXFR zone transfer attempt against a specific name server. |
| `subfinder -d inlanefreight.com -v`                 | Brute-forcing subdomains.                                             |
| `host support.inlanefreight.com`                    | DNS lookup for the specified subdomain.                               |
Subdomain wordlists and their word counts. 
```sh
500 /usr/share/wordlists/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt
1419 /usr/share/wordlists/seclists/Discovery/DNS/services-names.txt
2280 /usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt
3430 /usr/share/wordlists/seclists/Discovery/DNS/tlds.txt
4989 /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
5370 /usr/share/wordlists/seclists/Discovery/DNS/subdomains-spanish.txt
19966 /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
20000 /usr/share/wordlists/seclists/Discovery/DNS/italian-subdomains.txt
49928 /usr/share/wordlists/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt
64721 /usr/share/wordlists/seclists/Discovery/DNS/shubs-stackoverflow.txt
100000 /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
102582 /usr/share/wordlists/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt
114442 /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
151265 /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
484699 /usr/share/wordlists/seclists/Discovery/DNS/shubs-subdomains.txt
653920 /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt
1613291 /usr/share/wordlists/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt
2171687 /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt
3000001 /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt
4850604 /usr/share/wordlists/seclists/Discovery/DNS/FUZZSUBS_CYFARE_2.txt
5605156 /usr/share/wordlists/seclists/Discovery/DNS/FUZZSUBS_CYFARE_1.txt
```

**Subdomain and Vhost**
```
ffuf -u http://$TARGET -H "Host:FUZZ.$TARGET" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs <file size>
```

```
gobuster vhost -u http://<domain> -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain --xs 400 --ne
```

```shell
gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 
```

```sh
gobuster dns --domain <domain> --resolver <IP Address> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --ne
```

```shell
for sub in $(cat /usr/share/secLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```
 
**Reverse Whois (loop)**
[Amass](https://github.com/OWASP/Amass)
```

```

**Trackers**
[FaviHash](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)
```sh
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

# Directory Brute forcing

- `Discovery/Web-Content/common.txt`: This general-purpose wordlist contains a broad range of common directory and file names on web servers. It's an excellent starting point for fuzzing and often yields valuable results.
- `Discovery/Web-Content/directory-list-2.3-medium.txt`: This is a more extensive wordlist specifically focused on directory names. It's a good choice when you need a deeper dive into potential directories.
- `Discovery/Web-Content/raft-large-directories.txt`: This wordlist boasts a massive collection of directory names compiled from various sources. It's a valuable resource for thorough fuzzing campaigns.
- `Discovery/Web-Content/big.txt`: As the name suggests, this is a massive wordlist containing both directory and file names. It's useful when you want to cast a wide net and explore all possibilities.

```sh
sudo dirsearch --url http://$TARGET/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -f -e php,html,js,bak,zip,tgz,txt
-i 200,204,400,403 -x 500,502,429 -r -R 3 -o $TARGET.json
```

```sh
gobuster dir -u http://<domain> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
```

```shell
gobuster dir -u http://example.com/ -w wordlist.txt -s 200,301 --exclude-length 0
```

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://IP:PORT/FUZZ
```

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/w2ksvrus/FUZZ.html -e .php,.html,.txt,.bak,.js -v 
```

# Extensions Brute Force

```sh
ffuf -u http://<DOMAIN>/indexFUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt -fw xxx
```

# Recursion

```sh
ffuf -u http://<DOMAIN>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -recursion -recursion-depth 1 -e php,phps,php7 -fr "You don't have access\!" -fw 1
```

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion
```

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
```

```sh
feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u "http://dev.web1337.inlanefreight.htb:45864" -C 404 -x html --smart
```

# Parameter and Value Fuzzing

https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt

```sh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:31165/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774 -t 100
```

```sh
ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -u http://faculty.academy.htb:31165/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -t 100 -fs 781
```

```shell
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://IP:PORT/get.php?x=FUZZ"
```

```shell
ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```
# API Fuzzing

```python
python3 api_fuzzer.py http://IP:PORT
```

## Crawler
https://github.com/thewhiteh4t/FinalRecon
```
./finalrecon.py --url http://web1337.inlanefreight.htb:45864 --crawl
```

```
pip3 install scrapy --break-system-packages
```

```
python3 ReconSpider.py http://<domain>
```
# Misc

## Nikto

```
nikto -h http://<domain> -C all -Tuning -b
```

## SNMP

```
snmpwalk -v2c -c public 10.129.14.128
```

```
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt 10.129.2.50 -w 100
```

```
braa <community string>@<IP>:.1.3.6.*
```
