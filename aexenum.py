#!/usr/bin/env python3

import argparse
import threading
import subprocess

#parse arguments
parser = argparse.ArgumentParser()
parser.add_argument("domains_file", help="File containing a list of in-scope domains")
parser.add_argument("wordlist", help="Wordlist to use with gobuster")
parser.add_argument("common_name", help="Common name to use for output files")
parser.add_argument("-v", "--verbose", help="Enable verbosity", action="store_true")
parser.add_argument("--delete", help="Delete individual subfinder, sublist3r, and gobuster files after they are merged", action="store_true")
parser.add_argument("-a", "--all", help="Use root name servers as well for gobuster", action="store_true")
parser.add_argument("-s", "--shutdown", help="Shutdown when complete", action="store_true")
args = parser.parse_args()

#For gobuster, sends main domains to an array
with open(args.domains_file, 'r') as f:
    lines = f.read().splitlines()

#Get root nameservers
def get_rootnameservers():
    for line in lines:
        root_dig_command = f"dig @8.8.8.8 NS {line} +noedns +noall +answer | awk '{{print $5}}' | sed 's/\.$//' >> {args.common_name}-rootnameservers.temp"
        root_dig_command_verbose = f"dig @8.8.8.8 NS {line} +noedns +noall +answer | awk '{{print $5}}' | sed 's/\.$//' | tee -a {args.common_name}-rootnameservers.temp"
        if args.verbose:
            subprocess.run(root_dig_command, shell=True)
        else:
            subprocess.run(root_dig_command_verbose, shell=True)

    deduplicate_command = f"sort -u {args.common_name}-rootnameservers.temp | awk 'NF' > {args.common_name}-rootnameservers.txt"
    remove_command = f"rm {args.common_name}-rootnameservers.temp"
    subprocess.run(deduplicate_command, shell=True)
    subprocess.run(remove_command, shell=True)
#Whois Command
def get_whois():
    for line in lines:
        whois_command = f"whois {line} >> {args.common_name}-whois.txt"
        whois_command_verbose = f"whois {line} | tee -a {args.common_name}-whois.txt"

        if args.verbose:
            subprocess.run(whois_command_verbose, shell=True)
        else:
            subprocess.run(whois_command, shell=True)

def get_subfinder():
    subfinder_command = ["subfinder", "-dL", args.domains_file, "-all", "-o", f"{args.common_name}-subfinder.txt", "-silent"]
    subfinder_command_verbose = ["subfinder", "-dL", args.domains_file, "-all", "-o", f"{args.common_name}-subfinder.txt"]

    if args.verbose:
        subprocess.run(subfinder_command_verbose)
    else:
        subprocess.run(subfinder_command)

def get_gobuster():
    for line in lines:
        gobuster_command = f"gobuster dns -q -w {args.wordlist} -d {line} -t 150 -q | tee -a {args.common_name}-gobuster.temp"
        gobuster_command_verbose = f"gobuster dns -q -w {args.wordlist} -d {line} -t 150 | tee -a {args.common_name}-gobuster.temp"
        
        #Implement verbosity flag
        if args.verbose:
            subprocess.Popen(gobuster_command_verbose, shell=True)
            if args.all:
                                #Use root nameservers
                with open(f"{args.common_name}-rootnameservers.txt", "r") as rns:
                    nservers = rns.read().splitlines()
                    #Check the nservers list isn't empty
                    if len(nservers) > 0:
                        for nserver in nservers:
                                                        #Strip the leading whitespaces from the nameserver
                            nserver = nserver.strip()
                                                        #Run the command
                            gobuster_command_root_verbose = f"gobuster dns -r {nserver} -q -w {args.wordlist} -d {line} -t 150 | tee -a {args.common_name}-gobuster.temp"
                            subprocess.run(gobuster_command_root_verbose, shell=True)
        else:
            subprocess.Popen(gobuster_command, shell=True)
            if args.all:
                #Use root nameservers
                with open(f"{args.common_name}-rootnameservers.txt", "r") as f:
                    nservers = f.read().splitlines()
                    #Check the nservers list isn't empty
                    if len(nservers) > 0:
                        for nserver in nservers:
                                                        #Strip the leading whitespaces from the nameserver and make sure nserver is only the nameserver
                            nserver = nserver.strip()
                                                        #Run the command
                            gobuster_command_root = f"gobuster dns -r {nserver} -q -w {args.wordlist} -d {line} -t 150 -q | tee -a {args.common_name}-gobuster.temp"
                            subprocess.run(gobuster_command_root, shell=True)

    subprocess.run(f"grep -o 'Found: .*' {args.common_name}-gobuster.temp | cut -d \" \" -f2 >> {args.common_name}-gobuster.txt", shell=True)
    subprocess.run(["rm", f"{args.common_name}-gobuster.temp"])

def subdomain_merge():
    subfinder_file = f"{args.common_name}-subfinder.txt"
    gobuster_file = f"{args.common_name}-gobuster.txt"
    merge_file = f"{args.common_name}-subdomains.txt"
    subprocess.run(f"cat {subfinder_file} {gobuster_file} |  sort -u > {merge_file}", shell=True)
    if args.delete:
        subprocess.run(["rm", subfinder_file, gobuster_file])

def get_dig():
    dig_command = ["dns-info.py", f"{args.common_name}-subdomains.txt", args.common_name]
    subprocess.run(dig_command)

"""
NO LONGER USED: Now executed in dns-info.py
def get_vhosts():
    vhost_command = f"awk '{{if ($4 == \"A\") print $5}}' {args.common_name}-dns.txt | sort | uniq -c | sort -nr | awk '{{if ($1 > 1) print $2}}' | xargs -I {{}} grep {{}} {args.common_name}-dns.txt | awk '{{print $1, $5}}' > {args.common_name}-vhosts.txt"
    vhost_command_verbose = f"awk '{{if ($4 == \"A\") print $5}}' {args.common_name}-dns.txt | sort | uniq -c | sort -nr | awk '{{if ($1 > 1) print $2}}' | xargs -I {{}} grep {{}} {args.common_name}-dns.txt | awk '{{print $1, $5}}' | tee {args.common_name}-vhosts.txt"
    if args.verbose:
        subprocess.run(vhost_command_verbose, shell=True)
    else:
        subprocess.run(vhost_command, shell=True)
"""

def get_whatweb():
    whatweb_command = f"whatweb -i {args.common_name}-subdomains.txt --no-errors > {args.common_name}-whatweb.txt"
    whatweb_command_verbose = f"whatweb -i {args.common_name}-subdomains.txt --no-errors | tee {args.common_name}-whatweb.txt"
    if args.verbose:
        subprocess.run(whatweb_command_verbose, shell=True)
    else:
        subprocess.run(whatweb_command, shell=True)

def get_wafw00f():
    wafw00f_command = ["wafw00f", "-i", f"{args.common_name}-subdomains.txt", "-o", f"{args.common_name}-wafw00f.txt"]
    wafw00f_command_verbose = ["wafw00f", "-i",  f"{args.common_name}-subdomains.txt", "-o", f"{args.common_name}-wafw00f.txt", "-v"]

    if args.verbose:
        subprocess.run(wafw00f_command_verbose)
    else:
        subprocess.run(wafw00f_command)


def get_waybackurls():
    for line in lines:
        waybackurls_command = f"waybackurls {line} >> {args.common_name}-juicyinfo.txt"
        waybackurls_command_verbose = f"waybackurls {line} | tee -a {args.common_name}-juicyinfo.txt"

        if args.verbose:
            subprocess.Popen(waybackurls_command_verbose, shell=True)
        else:
            subprocess.Popen(waybackurls_command, shell=True)


get_rootnameservers()
get_whois()
subdomain_threads = [threading.Thread(target=get_subfinder), threading.Thread(target=get_gobuster)]
for thread in subdomain_threads:
    thread.start()
for thread in subdomain_threads:
    thread.join()
subdomain_merge()
other_threads = [threading.Thread(target=get_dig), threading.Thread(target=get_wafw00f),
                 threading.Thread(target=get_waybackurls), threading.Thread(target=get_whatweb)]
for thread in other_threads:
    thread.start()
for thread in other_threads:
    thread.join()
print("-------------------------------------------")
print("ENUMERATION COMPLETE")
print("-------------------------------------------")
if args.shutdown:
    subprocess.run("shutdown now", shell=True)
