import requests
import json

class DNS:
    def __init__(self, token):
        self.token = token

    #https://api.shodan.io/dns/domain/
    #Get all the subdomains for the given domain.
    def domain(self, d):
        r = json.loads(requests.get("https://api.shodan.io/dns/domain/{}".format(d),
                       params = {"key" : self.token}).text)
        try: 
            return r["subdomains"]
        except KeyError:
            return []

    #https://api.shodan.io/dns/resolve
    #look up the IP address for the provided host.
    def resolve(self, host):
        r = json.loads(requests.get("https://api.shodan.io/dns/resolve",
                       params = {"hostnames" : host, "key" : self.token}).text)
        return list(r.values())
    
    #https://api.shodan.io/dns/reverse
    #Look up the hostnames that have been defined for the given IP addresses.
    def reverse(self, ip):
        r = json.loads(requests.get("https://api.shodan.io/dns/reverse",
                       params = {"ips" : ip, "key" : self.token}).text)

        #the api returns a dict with the ip as key and a list.. ugly but it works
        r = [ d for i in r.values() for d in i] 
        return r


    #TODO: subdomain fuzzing
