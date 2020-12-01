import shodan 
import json

#Contains informations about a CVE
class CVE:
    def __init__(self, name, cvss, references, summary):
        self.name = name
        self.cvss = float(cvss)
        self.references = references
        self.summary = summary

#Parse json file returned by Shodan.hosts() 
class HostParser:
    def __init__(self, source):
        #ip, postal_code, city, last_update, country, os, org, ports, vulns, services
        self.ip = source["ip_str"]
        self.postal_code = source["postal_code"]
        self.country_code = source["country_code"]
        self.city = source["city"]
        self.last_update = source["last_update"]
        self.country = source["country_name"]
        self.os = source["os"]
        self.org = source["org"]
        self.data = source["data"]
        self.vulns = vulns(source)
        
        try:
            self.ports = [ d["port"] for d in source["data"] ]
            self.ports.sort()
        except KeyError:
            pass
        
    #returns attribute value of name
    #valid arguments: ip, postal_code, city, last_update, country, os, org, ports, vulns, services
    def get(self, name):
        if name in ["ip", "postal_code", "city", "last_update", "country", 
                    "os", "data", "org", "ports", "vulns", "services"]:

            return getattr(self, name)

    def getAttr(self):
        return ["ip", "postal_code", "city", "last_update", "country", 
                    "data", "os", "org", "ports", "vulns", "services"]

def vulns(source):
    #Extract vulns
    try:
        vulns = []
        for i in source["data"]:
            if "vulns" in i.keys():
                for v in i["vulns"]:
                    tmp = CVE(v, i["vulns"][v]["cvss"], i["vulns"][v]["references"], i["vulns"][v]["summary"])
                    vulns.append(tmp)
                break
    except KeyError:
        pass
    
    return vulns


