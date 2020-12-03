import requests
import json

class DNS:
    def __init__(self, token):
        self.token = token

    #https://api.shodan.io/dns/domain/
    #Get all the subdomains for the given domain.
    def domain(d):
        r = json.loads(requests.get("https://api.shodan.io/dns/domain/{}".format(d),
                       params = {"key" : token}).text)
        return r["subdomains"]

    #https://api.shodan.io/dns/resolve
    #look up the IP address for the provided host.
    def resolve(selfm host):
        r = json.loads(requests.get("https://api.shodan.io/dns/resolve", 
                       params = {"key" : self.token}).text)
        return r
    
    #https://api.shodan.io/dns/reverse
    #Look up the hostnames that has been defined for the given IP addresses.
    def reverse(self, ip):
        r = json.loads(requests.get("https://api.shodan.io/dns/reverse",
                       params = {"ips" : ip, "key" : self.token}).text)
        return r[list(r.keys())[0]]

    #TODO: subdomain fuzzing
