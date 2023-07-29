#!/usr/bin/env python3

import argparse
import threading
import subprocess

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument("domains_file", help="File containing a list of in-scope domains")
parser.add_argument("wordlist", help="Wordlist to use with gobuster")
parser.add_argument("common_name", help="Common name to use for output files")
parser.add_argument("-v", "--verbose", help="Enable verbosity", action="store_true")
parser.add_argument("--delete", help="Delete individual subfinder, sublist3r, and gobuster files after they are merged",
                    action="store_true")
parser.add_argument("-a", "--all", help="Use root name servers as well for gobuster", action="store_true")
parser.add_argument("-s", "--shutdown", help="Shutdown when complete", action="store_true")
args = parser.parse_args()

# For gobuster, sends main domains to an array
with open(args.domains_file, 'r') as f:
    lines = f.read().splitlines()


# Get root nameservers
def get_rootnameservers():
    for line in lines:
        if args.verbose:
            root_dig_command_verbose = f"dig NS {line} +noedns +short | tee -a {args.common_name}-rootnameservers.temp"
            subprocess.run(root_dig_command_verbose, shell=True)
        else:
            root_dig_command = f"dig NS {line} +noedns +short >> {args.common_name}-rootnameservers.temp"
            subprocess.run(root_dig_command, shell=True)

    # Deduplicate the root nameservers file
    deduplicate_command = f"sort -u {args.common_name}-rootnameservers.temp | awk 'NF' > {args.common_name}-rootnameservers.txt"
    # Remove the temporary nameserver file
    remove_command = f"rm {args.common_name}-rootnameservers.temp"

    # Run the commands
    subprocess.run(deduplicate_command, shell=True)
    subprocess.run(remove_command, shell=True)


# Whois Command
def get_whois():
    for line in lines:
        if args.verbose:
            whois_command_verbose = f"whois {line} | tee -a {args.common_name}-whois.txt"
            subprocess.run(whois_command_verbose, shell=True)
        else:
            whois_command = f"whois {line} >> {args.common_name}-whois.txt"
            subprocess.run(whois_command, shell=True)


def get_subfinder():
    if args.verbose:
        subfinder_command_verbose = ["subfinder", "-dL", args.domains_file, "-all", "-o",
                                     f"{args.common_name}-subfinder.txt"]
        subprocess.run(subfinder_command_verbose)
    else:
        subfinder_command = ["subfinder", "-dL", args.domains_file, "-all", "-o", f"{args.common_name}-subfinder.txt",
                             "-silent"]
        subprocess.run(subfinder_command)


def get_gobuster():
    # Gobuster will run an instance for each domain in the domain file.
    final_commands = []
    for line in lines:
        final_commands.append(
            f"gobuster dns -q -w {args.wordlist} -d {line} -t 150 | tee -a {args.common_name}-gobuster.temp")
        if args.all:
            # Use root nameservers / MAY TAKE A VERY LONG TIME for LITTLE REWARD
            with open(f"{args.common_name}-rootnameservers.txt", "r") as rns:
                nservers = rns.read().splitlines()
                # Check the nservers list isn't empty
                if len(nservers) > 0:
                    for nserver in nservers:
                        # Strip the leading whitespaces from the nameserver
                        nserver = nserver.strip()
                        # Run the command
                        final_commands.append(
                            f"gobuster dns -r {nserver} -q -w {args.wordlist} -d {line} -t 150 | tee -a {args.common_name}-gobuster.temp")
    processes = [subprocess.Popen(cmd, shell=True) for cmd in final_commands]
    for process in processes:
        process.wait()


# Deletes gobuster's temporary files
def delete_temp():
    subprocess.run(
        f"grep -o 'Found: .*' {args.common_name}-gobuster.temp | cut -d \" \" -f2 >> {args.common_name}-gobuster.txt",
        shell=True)
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

# No longer used
def get_vhosts():
    if args.verbose:
        vhost_command_verbose = f"awk '{{if ($4 == \"A\") print $5}}' {args.common_name}-dns.txt | sort | uniq -c | sort -nr | awk '{{if ($1 > 1) print $2}}' | xargs -I {{}} grep {{}} {args.common_name}-dns.txt | awk '{{print $1, $5}}' | tee {args.common_name}-vhosts.txt"
        subprocess.run(vhost_command_verbose, shell=True)
    else:
        vhost_command = f"awk '{{if ($4 == \"A\") print $5}}' {args.common_name}-dns.txt | sort | uniq -c | sort -nr | awk '{{if ($1 > 1) print $2}}' | xargs -I {{}} grep {{}} {args.common_name}-dns.txt | awk '{{print $1, $5}}' > {args.common_name}-vhosts.txt"
        subprocess.run(vhost_command, shell=True)


def get_whatweb():
    add_new_line = ""
    if args.verbose:
        whatweb_command_verbose = f"whatweb -i {args.common_name}-subdomains.txt -a=3 --no-errors | tee {args.common_name}-whatweb.txt"
        subprocess.run(whatweb_command_verbose, shell=True)
    else:
        whatweb_command = f"whatweb -i {args.common_name}-subdomains.txt -a=3 --no-errors > {args.common_name}-whatweb.txt"
        subprocess.run(whatweb_command, shell=True)


def get_wafw00f():
    if args.verbose:
        wafw00f_command_verbose = ["wafw00f", "-i", f"{args.common_name}-subdomains.txt", "-o",
                                   f"{args.common_name}-wafw00f.txt", "-v"]
        subprocess.run(wafw00f_command_verbose)
    else:
        wafw00f_command = ["wafw00f", "-i", f"{args.common_name}-subdomains.txt", "-o",
                           f"{args.common_name}-wafw00f.txt"]
        subprocess.run(wafw00f_command)


def get_waybackurls():
    for line in lines:
        if args.verbose:
            waybackurls_command_verbose = f"waybackurls {line} | tee -a {args.common_name}-juicyinfo.txt"
            subprocess.run(waybackurls_command_verbose, shell=True)
        else:
            waybackurls_command = f"waybackurls {line} >> {args.common_name}-juicyinfo.txt"
            subprocess.run(waybackurls_command, shell=True)


get_rootnameservers()
get_whois()
subdomain_threads = [threading.Thread(target=get_subfinder), threading.Thread(target=get_gobuster)]
for thread in subdomain_threads:
    thread.start()
for thread in subdomain_threads:
    thread.join()
delete_temp()
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
