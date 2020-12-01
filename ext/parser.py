import shodan 
import json

#Contains informations about a CVE
class CVE:
    def __init__(self, name, cvss, references, summary):
        self.name = name
        self.cvss = float(cvss)
        self.references = references
        self.summary = summary

#Contains informations about a service
class Service:
    def __init__(self, server, port, protocol, hostnames, data, isp):
        self.server = server
        self.port = port
        self.protocol = protocol
        self.hostnames = hostnames
        self.data = data
        self.isp = isp

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

        #Extract ports
        try:
            self.ports = [ d["port"] for d in source["data"] ]
            self.ports.sort()
        except KeyError:
            pass

        #Extract vulns
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

        #Extract services, damn this is so ugly -Alex
        try:
            self.services = []
            for s in source["data"]:
                if "http" in s.keys():
                    server = s["http"]["server"] if s["http"]["server"] else "Unkown web-server"
                elif "ssh" in s.keys():
                    server = s["product"] + " " + s["version"]
                elif "ftp" in s.keys():
                    server = "FTP Anon login" if s["ftp"]["anonymous"] else "FTP"
                else:
                    server = "Unknown service"

                port = s["port"]
                protocol = s["transport"]
                hostnames = s["hostnames"]
                isp = s["isp"]
                data = s["data"]
                self.services.append(Service(server, port, protocol, hostnames, data, isp))

        except KeyError:
            pass
         
    #returns attribute value of name
    #valid arguments: ip, postal_code, city, last_update, country, os, org, ports, vulns, services
    def get(self, name):
        if name in ["ip", "postal_code", "city", "last_update", "country", 
                    "os", "org", "ports", "vulns", "services"]:

            return getattr(self, name)
        else:
            return ""
