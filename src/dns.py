import requests
import json

class DNS:
    def __init__(self, token):
        self.token = token

    def domain(self, d):
    #https://api.shodan.io/dns/domain/
    #Get all the subdomains for the given domain.
        r = json.loads(requests.get("https://api.shodan.io/dns/domain/{}".format(d),
                       params = {"key" : self.token}).text)
        try: 
            return r["subdomains"]
        except KeyError:
            return []

    def resolve(self, host):
    #https://api.shodan.io/dns/resolve
    #look up the IP address for the provided host.
        r = json.loads(requests.get("https://api.shodan.io/dns/resolve",
                       params = {"hostnames" : host, "key" : self.token}).text)
        return list(r.values())
    
    def reverse(self, ip):
    #https://api.shodan.io/dns/reverse
    #Look up the hostnames that have been defined for the given IP addresses.
        r = json.loads(requests.get("https://api.shodan.io/dns/reverse",
                       params = {"ips" : ip, "key" : self.token}).text)

        #the api returns a dict with the ip as key and a list.. ugly but it works
        try:
            r = [ d for i in r.values() for d in i] 
            return r
        except:
            return []
