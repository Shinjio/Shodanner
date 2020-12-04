import readline
import colorama
import sys
import os

from cmd import Cmd
from .shodanner import Shodanner
 
class Host(Cmd):
    """Host Class, used to handle HostParser objects"""
    def __init__(self, host):
        super(Host, self).__init__()
        self.host = host

    def do_get(self, args):
        """Get an attribute from the host object (see the wiki for information about the HostParser object.)"""
        if args == "vulns":
            for i in self.host.vulns:
                print(i.name + ": " + str(i.cvss) + " - " + i.references[0])
        else:
            print(getattr(self.host, args))

    def do_list(self, args):
        """List HostParser object's attributes (the ip you just entered).\nthe data attribute produces HUGE output"""
        attribs = [i for i in self.host.__dict__.keys() if not i.startswith('_')]
        print(attribs)

    def do_exit(self, args):
        """Exit"""
        return True

class Interactive(Cmd):
    def __init__(self):
        super(Interactive, self).__init__()
        self.shodanner = Shodanner("config.json");

    def do_quickSearch(self, query):
        """Do a scan with with your custom query, returns 25 ips"""
        for i in self.shodanner.quickSearch(query):
            print(i)

    def do_exploitdb(self, query):
        """Look for an exploit on exploitDB."""
        print(self.shodanner.exploit.searchExploitDB(query))

    def do_cvedetails(self, query):
        """Look for info about a CVE on CVEDetails."""
        print(self.shodanner.exploit.searchCVEDetails(query))

    def do_info(self, args):
        """Return information about a specific IP"""
        os.system('clear')
        host = self.shodanner.host(args)
        print(colorama.Fore.YELLOW + "You can now access each attribute by simply typing \"get\" followed by it's name, type \"list\" to see the attributes\n" + colorama.Fore.WHITE)

        prompt = Host(host)
        prompt.prompt =   "[" + colorama.Fore.RED + f"{host.ip}" + colorama.Fore.WHITE+ "] " + "⪢ " 
        prompt.cmdloop()

    def do_myip(self, args):
        """Returns your IP address."""
        print(self.shodanner.myip())

    def do_profile(self,args):
        """Returns information about your profile."""
        print(self.shodanner.profile())

    def do_scan(self, args):
        """Crawl an IP address, might take a while."""
        print(self.shodanner.scan(args)) 

    def do_scanStatus(self, args):
        """Check the process of a previously submitted scan request.\n
        Possible values for the status are: SUBMITTING, QUEQUE, PROCESSING, DONE
        """
        print(self.shodanner.scanStatus(args))

    def do_reverse(self,args):
        """Look up the hostnames that have been defined for the given IP addresses."""
        print(self.shodanner.dns.domain(args))

    def do_domain(self,args):
        """Get all the subdomains for a given domain"""
        print(self.shodanner.dns.domain(args))

    def do_resolve(self, args):
        """Look up the IP address provided"""
        print(self.shodanner.dns.resolve(args))

    def do_honeyscore(self,args):    
        """Calculates a honeypot probability score ranging from 0 (not a honeypot) to 1.0 (is a honeypot)"""
        print(self.shodanner.honeyscore(args))

    def do_clear(self, args):
        """Clear the screen"""
        os.system('clear')

    def do_exit(self, args):
        """Close shodanner"""
        sys.exit()
