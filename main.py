import argparse
import readline
import colorama
import os

from src.shodanner import Shodanner

if __name__ == "__main__":
    #Move to root project dir
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ROOT_DIR)

    
    #Shodanner object
    shodanner = Shodanner("config.json")
   
    #what do we want to do?
    #print(shodanner.search(query="port: 80"))
    honeypot = shodanner.honeyscore("87.0.243.202")
    print(honeypot)
