#Here's, a quick demo
#create Shodanner object
from src.shodanner import Shodanner
import time

s = Shodanner("config.json")

#let's search 15 ips matching our query
ips = s.quickSearch(query='city:"Cagliari" port:80', results=15)

#wait one second (request rate limit is set to 1 request / second
#by default 

#enumerate the hosts found with the hosts method,
#it will return an object of the HostParser class,
#we will access its attributes later to check for
#vulns. Notice how we must wait one second between
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

