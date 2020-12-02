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
    def __init__(self, source, minify=False, history=False):
        #ip, postal_code, city, last_update, country, os, org, ports, vulns, services
        try:
            self.ip = source["ip_str"]
            self.country_code = source["country_code"]
            self.city = source["city"]
            self.last_update = source["last_update"]
            self.country = source["country_name"]
            self.os = source["os"]
            self.data = source["data"]
            self.vulns = vulns(source)
            self.ports = [ d["port"] for d in source["data"] ]
            self.ports.sort()
            
            if minify or history:
                pass
            else:
                self.postal_code = source["postal_code"]
                self.org = source["org"]
        except KeyError as e:
            print(str(e))
        
    #returns attribute value of name
    #valid arguments: ip, postal_code, city, last_update, country, os, org, ports, vulns, services
    def get(self, name):
        if hasattr(self, name):
            return getattr(self, name)
        else:
            return 
    
    def listAttr(self):
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


