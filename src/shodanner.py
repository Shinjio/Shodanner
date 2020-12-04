import requests
import shodan
import json
import os

from .loader import Loader
from ext.ext import buildQuery
from ext.parser import HostParser
from .exploit import Exploit
from .dns import DNS

#Main class
class Shodanner:
    def __init__(self, file=None, token=""):
        """
        path : path to config.json
        """
        if file:
            #Load config.json 'api'
            config = Loader(file)
            self.token = config.get("api")
            self.api = shodan.Shodan(self.token)
        elif token:
            self.token = token
            self.api = shodan.Shodan(token)
        else:
            return None
        
        self.exploit = Exploit()
        self.dns = DNS(self.token) 

    def quickSearch(self, query=None, port=None, os=None, results=None, hostname=None, country=None, output=None, filters=["ip_str"]):
        """
        expected arguments:
            query : custom query, str
            port : int
            os : str
            results : number of expected results, int
            hostname : str
            country : str (2 chars, ex: IT, FR, UK)
            output : output file, str
            filters : list of filters we want to grab from the scan, list
        """

        query = query if query else buildQuery(port,os,hostname,country)
        results = 10 if not results else results

        r = 0 #results counter
        ret = "" #final output
        for device in self.api.search_cursor(query):
            if r == results: #break if we reach results limit
                break
            data = json.dumps(device) #device r's information
            #now we add the output for each filter
            for i in filters:
                try:
                    ret += device[i]
                except KeyError:
                    ret += "None\n"
                except Exception as e:
                    print("[!] Caught exception for filter '{}' in device {}... Continuing...".format(i, r+1))
                    continue
                ret += "\n"
            r += 1
        #check if we want to write ret to a file, or just return it
        if output:
            with open(output, 'w') as f:
                f.write(ret)
        else:
            ret = [i for i in ret.split("\n") if i != '']
            return ret
    
    def getFilters(self):
        return "asn ,cpe ,data, devicetype, domains, hash, hostnames, http, info, ip, ip_str, isp, location, org, os, port, product, _shodan, tags, timestamp, transport, version, vulns"

    def host(self, ip, history=False, minify=False):
        try:
        #if type is invalid
            if ((type(history) or type(bool)) != bool) or type(ip) != str:
                print("One or more parameters are invalid... returning.")
                return
            info = self.api.host(ip, history=history, minify=minify)
        except APIError:
            return

        return HostParser(info, minify=minify, history=history)

    #Get your current IP address as seen from the internet
    def myip(self):
        return requests.get("https://api.shodan.io/tools/myip",
                            params = {"key" : self.token}).text
    
    #Returns information about the Shodan account linked to this API key
    def profile(self):
        return json.loads(requests.get("https://api.shodan.io/api-info",
                                        params = {"key" : self.token}).text)

    #Calculates a honeypot probability score ranging from 0 (not a honeypot) to 1.0 (is a honeypot)
    def honeyscore(self, ip):
        return float(requests.get("https://api.shodan.io/labs/honeyscore/" + ip,
                                   params = {"key" : self.token}).text)
