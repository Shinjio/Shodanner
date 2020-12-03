hodanner
Shodanner is an API wrapper for the [shodan](https://shodan.io) API.
Other than the classic API functions we added some spicy stuff that you can use for your spicy hacking.

## Features
The programmer using this library is free to use the [base functions](https://developer.shodan.io/api) that the API provides or the more interesting functions we developed:
- Automated host enumeration
	- enumerate info, open ports and vulns of a device
- Exploits finder 
	-  Given a vulnerability look for a PoC in different exploit databases 
	- even with a free API plan!
 
 ## Installation
Install the python dependencies:
`pip3 install -r requirements.txt` 

configure config.json with your api token:
```json
alex@pepe$: vim config.json
{
    "api":"your token here"
}
```
## Usage
```py
#Here's, a quick demo
#create Shodanner object
from src.shodanner import Shodanner
import time

s = Shodanner("config.json")

#let's search 15 ips matching our query
ips = s.quickSearch(query='country:"CN" port:80', results=5)

#Notice how we must wait one second between
#each request, that's because shodan has a 1 request
#per second limit.
hosts = []
for i in ips:
    hosts.append(s.host(i))
    time.sleep(1)

#let's print the vulnerable devices with each CVE
for host in hosts:
    for vuln in host.vulns:
        print(f"[{host.ip}] {vuln.name} {vuln.cvss} - {vuln.references[0]}")
```
for more details visit the [wiki](https://github.com/shinjio/Shodanner/wiki) . (that is a work in progress)

## Work in progress

The project is still growing, more feature will come and we are open to suggestions:

Discord:
- Makise#9290
- Askesis#0327 
- [Discord server](https://discord.gg/8WEjxWPgFy)
