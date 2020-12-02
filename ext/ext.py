def buildQuery(port, os, hostname, country):
    query = ""
    if port:
        query += 'port:' + str(port) + ' '
    if os:
        query += 'os:' + os + ' '
    if hostname:
        query += 'hostname: ' + hostname + ' '
    if country:
        query += 'country: ' + country + ' '
    return query

def getFilters():
    filtersList = """\nasn 
cpe 
data 
devicetype 
domains 
hash 
hostnames 
http 
info 
ip 
ip_str
isp 
location
org 
os 
port 
product 
_shodan 
tags 
timestamp 
transport 
version 
vulns
    """
    

    filters = input("Type the filters you need to get separated by a comma. (?list) ")
    while filters == "?list":
        print(filtersList)
        filters = input("Type the filters you need to get separated by a comma. (?list) ")
    filters = filters.split(',')
    
    return filters
