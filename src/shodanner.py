import shodan
import json
import os

from .loader import Loader
from ext.ext import getFilters, buildQuery

#Main class
class Shodanner:
    def __init__(self):
        #Load config.json 'api'
        config = Loader("config.json")
        self.api = shodan.Shodan(config.get("api"))
 
    def scan(self, **args):

        #main scanner args
        port = args['port']
        os = args['os']
        results = args['results'] if args['results'] else 20
        hostname = args['hostname']
        country = args['country']
        output = args['output']
        filters = getFilters()
        query = buildQuery(port, os, hostname, country) 

        i = 0
        if output:
            with open(output, 'w') as f:
                for device in self.api.search_cursor(query):
                    if i == results:
                        break

                    data = json.dumps(device)
                    msg = ""
                    f.write("Device n° " + str(i+1) + ":"+"\n")
                    
                    for j in filters:
                        try:
                            if j == "vulns":
                                msg += "[*] " + j + ": "
                                for a in device[j]:
                                    msg += a + ", "
                            else:
                                msg += "[*] " + j + ": " + str(device[j])
                        except KeyError:
                            msg += "None"
                        except Exception as e:
                            msg += "[!] " + j + " skipped, " + str(e)

                    f.write("\n" + msg + "\n")
                    #f.write(json.dumps(device))
                    i +=1
