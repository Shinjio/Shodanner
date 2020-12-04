import readline
import colorama
import sys

from cmd import Cmd
from .shodanner import Shodanner

class Interactive(Cmd):
    def __init__(self):
        super(Interactive, self).__init__()
        self.shodanner = Shodanner("config.json");
    
    def do_scan(self, query):
        """Do a scan with with your custom query, returns 25 ips"""
        for i in self.shodanner.quickSearch(query):
            print(i)

    def do_clear(self, args):
        print("\033[2J")

    def do_exit(self, args):
        sys.exit()

if __name__ == "__main__":
    prompt = Interactive()
    print("\033[2J")
    prompt.prompt =  colorama.Fore.LIGHTRED_EX + "\u0332shodanner " + "⪢ " + colorama.Fore.WHITE
    prompt.cmdloop()
    

