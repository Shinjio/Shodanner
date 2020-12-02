def buildQuery(port, os, hostname, country):
    query = ""
    if port:
        query += 'port:' + str(port) + ' '
    if os:
        query += 'os:' + os + ' '
    if hostname:
        query += 'hostname:' + hostname + ' '
    if country:
        query += 'country:' + country + ' '
    return query
