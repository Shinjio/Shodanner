import shodan
import json
import os

from .loader import Loader
from ext.ext import getFilters, buildQuery

#Main class
class Shodanner:
    def __init__(self, path):
        """
        path : path to config.json
        """

        #Load config.json 'api'
        config = Loader(path)
        self.api = shodan.Shodan(config.get("api"))


    def scan(self, query=None, port=None, os=None, results=None, hostname=None, country=None, output=None, filters=["ip_str"]):
        """
        expected arguments:
            custom : custom query, str
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
            return ret
            

        """
        i = 0
        if output:
            with open(output, 'w') as f:
                for device in self.api.search_cursor(query):
                    if i == results:
                        break

                    data = json.dumps(device)
                    msg = ""
                    f.write("\nDevice n° " + str(i+1) + ":")
                    
                    for j in filters:
                        try:
                            if j == "vulns":
                                msg += "[*] " + j + ": "
                                for a in device[j]:
                                    msg += a + ", "
                                msg += "\n"
                            else:
                                msg += "[*] " + j + ": " + str(device[j]) + "\n"
                        except KeyError:
                            msg += "None\n"
                        except Exception as e:
                            msg += "[!] " + j + " skipped, " + str(e) + "\n"

                    f.write("\n" + msg + "\n")
                    #f.write(json.dumps(device))
                    i +=1
        """
