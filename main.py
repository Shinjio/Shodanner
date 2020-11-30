import argparse
import readline
import colorama
import os

from src.shodanner import Shodanner

if __name__ == "__main__":
    #Move to root project dir
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ROOT_DIR)

    t = "search"
    
    #Shodanner object
    shodanner = Shodanner("config.json")
   
    #what do we want to do?
    if t == "search":
        print(shodanner.search(query="port: 80"))
    elif t == "exploits":
        shodanner.exploits()
    else:
        shodanner.custom()

