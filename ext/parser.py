import shodan 
import json

#Simple class containing informations about a CVE
class CVE:
    def __init__(self, name, cvss, references, summary):
        self.name = name
        self.cvss = float(cvss)
        self.references = references
        self.summary = summary

#Parse json file returned by Shodan.hosts() 
class HostParser:
    def __init__(self, source):
        self.ip = source["ip_str"]
        self.postal_code = source["postal_code"]
        self.country_code = source["country_code"]
        self.city = source["city"]
        self.last_update = source["last_update"]
        self.country = source["country_name"]
        self.os = source["os"]
        self.org = source["org"]

        #Try to extract ports and vulns
        try:
            self.ports = [ d["port"] for d in source["data"] ]
            self.ports.sort()
        except KeyError:
            pass

        try:
            self.vulns = []
            for i in source["data"]:
                if "vulns" in i.keys():
                    for v in i["vulns"]:
                        tmp = CVE(v, i["vulns"][v]["cvss"], i["vulns"][v]["references"], i["vulns"][v]["summary"])
                        self.vulns.append(tmp)
                    break
        except KeyError:
            pass

    #Display host data    
    def display(self):
        print("ip:           ", self.ip)
        print("postal_code:  ", self.postal_code)
        print("country code: ", self.country_code)
        print("country:      ", self.country)
        print("city:         ", self.city)
        print("org:          ", self.org)
        print("os:           ", self.os)
        
        print("\n")
        if self.ports:
            print("Ports:", end="")
            for p in self.ports:
                if self.ports.index(p) % 5 == 0:
                    print(f"\n\t{p:<4}", end="")
                else:
                    print(f" - {p}", end="")

        print("\n")
        if self.vulns:
            print("Vulnerabilities:")
            for v in self.vulns:
                print(f"\t{v.name:<14} {v.cvss} - {v.references[0]}")
