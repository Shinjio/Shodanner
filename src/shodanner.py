import requests
import shodan
import json
import os

from .loader import Loader
from ext.ext import buildQuery
from ext.parser import HostParser
from .exploit import Exploit

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
        #if type is invalid
        if ((type(history) or type(bool)) != bool) or type(ip) != str:
            print("One or more parameters are invalid... returning.")
            return
        return HostParser(self.api.host(ip, history=history, minify=minify), minify=minify, history=history)

    def honeyscore(self, ip):
        return requests.get("https://api.shodan.io/labs/honeyscore/{}?key={}".format(ip, self.token)).text 
    
