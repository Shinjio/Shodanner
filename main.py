import argparse
import readline
import colorama
import os

from src.shodanner import Shodanner
from src.loader import Loader

def parser():
     #Create parser
    parser = argparse.ArgumentParser()
    parser.add_argument("type", 
            help="choose wether to scan for ips or look for exploits",
            choices=["scan", "custom", "exploits"])
    parser.add_argument("--port", type=int, help="port to search")
    parser.add_argument("--hostname", help="hostname to search")
    parser.add_argument("--os", help="os to search")
    parser.add_argument("--country", help="country to search")
    parser.add_argument("--output", help="write output to file")
    parser.add_argument("--results", type=int, help="number of ips to look for")
    
    #args as dictionary
    args = parser.parse_args()
    return args 

if __name__ == "__main__":
    #Move to root project dir
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ROOT_DIR)
    
    #get arguments as dictionary
    args = vars(parser())

    #Shodanner object
    shodanner = Shodanner()
   
    #what do we want to do?
    if args['type'] == "scan":
        shodanner.scan(**args)
    elif args['type'] == "exploits":
        shodanner.exploits()
    else:
        shodanner.custom()

