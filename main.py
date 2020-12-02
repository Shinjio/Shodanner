""" THIS IS USED FOR TESTING PURPOSES ONLY """


import argparse
import readline
import colorama
import os
import shodan

from src.loader import Loader
from src.shodanner import Shodanner

if __name__ == "__main__":
    #Move to root project dir
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ROOT_DIR)

    conf = Loader("config.json")

    api = shodan.Shodan(conf.get("api"))
    #Shodanner object
    shodanner = Shodanner("config.json")

    ips = shodanner.quickSearch(port=80, results=10)
    print(ips)

    """
    ips = shodanner.quickSearch(port=80, results=10)
    a = []
    for i in ips.split('\n'):
        if i == '':
            pass
        else:
            a.append(i)
    print(a)
    """


    #what do we want to do?
    #print(shodanner.search(query="port: 80"))
    #ip = "87.0.243.202"
    #host = shodanner.host(ip, minify=True, history=True)
    #host = api.host(ip, minify=True, history=True)

