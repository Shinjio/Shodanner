#Here's, a quick demo
from src.shodanner import Shodanner
import time

#create Shodanner object
s = Shodanner("config.json")

#let's search 5 ips matching our query
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
