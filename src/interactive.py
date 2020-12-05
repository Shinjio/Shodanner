import shodan
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

    def emptyline(self):
        pass

    def do_get(self, args):
        """Get an attribute from the host object (see the wiki for information about the HostParser object.)"""
        if args:
            if args == "vulns":
                for i in self.host.vulns:
                    print(i.name + ": " + str(i.cvss) + " - " + i.references[0])
            else:
                print(getattr(self.host, args))
        else:
            print("please insert a valid attribute")

    def do_list(self, args):
        """List HostParser object's attributes (the ip you just entered).\nthe data attribute produces HUGE output"""
        attribs = [i for i in self.host.__dict__.keys() if not i.startswith('_')]
        print(attribs)

    def do_exit(self, args):
        """Exit"""
        return True

""" NOTES 05/12/2020 Alex:
        i wrote some error handling, the error messages should be changed
        with something like a print of the syntax of the command or other,
        i'm not good at formatting either, must improve for later commits.
"""

class Interactive(Cmd):
    def __init__(self):
        super(Interactive, self).__init__()
        self.shodanner = Shodanner("config.json");

    def emptyline(self):
        pass

    def do_quickSearch(self, query):
        """Do a scan with with your custom query, returns 25 ips"""
        if query: 
            for i in self.shodanner.quickSearch(query):
                print(i)
        else:
            print("please enter a valid shodan query")
    
    #DONE
    def do_exploitdb(self, query):
        """Look for an exploit on exploitDB."""
        if query:
            for e in self.shodanner.exploit.searchExploitDB(query):
                print(e)
        else:
            print("please enter an exploit name")

    #DONE
    def do_cvedetails(self, cve):
        """Look for info about a CVE on CVEDetails."""
        if cve.upper().startswith("CVE-"):
            for e in self.shodanner.exploit.searchCVEDetails(cve):
                print(e)
        else:
            print("please insert a valid cve name")

    
    #ALMOST DONE, there are probably other exception i didn't check in the Host cmd
    def do_info(self, args):
        """Return information about a specific IP"""
        if args:
            host = self.shodanner.host(args)
            if not host:
                print("coulndn't find the host ...maybe invalid ip?")
                return

            os.system('clear')
            print(colorama.Fore.YELLOW + "You can now access each attribute by simply typing \"get\" followed by it's name, type \"list\" to see the attributes\n" + colorama.Fore.WHITE)

            prompt = Host(host)
            prompt.prompt =   "[" + colorama.Fore.RED + f"{host.ip}" + colorama.Fore.WHITE+ "] " + "⪢ " 
            prompt.cmdloop()
        else:
            print("please insert a valid ip")
    
    #DONE
    def do_myip(self, args):
        """Returns your IP address."""
        print(self.shodanner.myip())

    #DONE
    def do_profile(self,args):
        """Returns information about your profile."""
        p = self.shodanner.profile()
        #TOFIX, i seriously suck at formatting
        print("""
        Usage limits:
            scan_credits: {}
            query_credits: {}
            monitored_ips: {}

        scan_credis: {}
        query_credits: {}
        unlocked_left: {}
        plan: {}\n""".format(p["usage_limits"]["scan_credits"], p["usage_limits"]["query_credits"], 
                           p["usage_limits"]["monitored_ips"], p["scan_credits"], 
                           p["query_credits"], p["unlocked_left"], p["plan"]))
              

    #DONE kinda, you should check if the ip is valid, apparently shodan will try
    #to scan an invalid ip endinding up wasting the credit, bruh.
    #Gosh, i finished my redbull.
    def do_scan(self, args):
        """Crawl an IP address, might take a while."""
        if args:
            s = self.shodanner.scan(args)
            try:
                print("count: {}\nid: {}\ncredits_left: {}".format(s["count"], 
                                                                   s["id"], s["credits_left"]))
            except KeyError:
                print(s["error"] + " ...maybe invalid ip?")
    
    #DONE
    def do_scanStatus(self, args):
        """Check the process of a previously submitted scan request.\n
        Possible values for the status are: SUBMITTING, QUEQUE, PROCESSING, DONE, NOT_FOUND
        """
        if args:
            print(self.shodanner.scanStatus(args))
        else:
            print("please insert a valid scan id")

    #DONE
    def do_reverse(self,args):
        """Look up the hostnames that have been defined for the given IP addresses."""
        dns = self.shodanner.dns.reverse(args)
        if type(dns) == list:
            for d in dns:
                print(d)
        else:
            print(dns)
    
    #DONE
    def do_domain(self,args):
        """Get all the subdomains for a given domain"""
        if args:
            sub = self.shodanner.dns.domain(args)
            if sub:
                for s in sub:
                    print(s)
            else:
                print("No subdomains found.")
        else:
            print("please insert a domain name")

    #DONE
    def do_resolve(self, args):
        """Look up the IP address provided"""
        if args:
            ips = self.shodanner.dns.resolve(args)
            for i in ips:
                print(i)
        else:
            print("please insert a domain name")
    
    #DONE
    def do_honeyscore(self,args):    
        """Calculates a honeypot probability score ranging from 0 (not a honeypot) to 1.0 (is a honeypot)"""
        if args:
            print(self.shodanner.honeyscore(args))
        else:
            print("please insert a valid ip")

    def do_clear(self, args):
        """Clear the screen"""
        os.system('clear')

    def do_EOF(self, args):
        "Close shodanner"""
        sys.exit()

    def do_exit(self, args):
        """Close shodanner"""
        sys.exit()
