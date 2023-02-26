#!/usr/bin/env python3

import subprocess
import sys
import os

# Check if the required number of arguments was provided
if len(sys.argv) != 3:
    print("Usage: dns-info.py <input_file> <project-name>")
    sys.exit(1)

# Get the input and output file names from the arguments
input_file = sys.argv[1]
dns_file = f"{sys.argv[2]}-dns.txt"
vhost_file = f"{sys.argv[2]}-vhosts.txt"
aaaa_vhost_file = f"{sys.argv[2]}-aaaa-vhosts.txt"
ip_file = f"{sys.argv[2]}-ip.txt"
ip_full_file = f"{sys.argv[2]}-ip-full.txt"
ipv6_file = f"{sys.argv[2]}-ipv6.txt"
ipv6_full_file = f"{sys.argv[2]}-ipv6-full.txt"
valid_subdomains_file = f"{sys.argv[2]}-valid-subdomains.txt"

def tryzonetransfer(domain, nameserver):
    try:
        zone_result = subprocess.run(["dig", "AXFR", domain, f"@{nameserver}", "+noall", "+answer"],
                                     capture_output=True)
        zone_transfer = zone_result.stdout.decode()
        if zone_transfer != "":
            return f"************Trying zone transfer for: {domain} using {nameserver}\n{zone_transfer.strip()}\n***\n"
    except:
        pass
    return ""


# Create an IP folder, where the IP addresses and vhosts will go
def create_folders(name):
    try:
        os.makedirs(name)
    except FileExistsError:
        print("Folder already exists! Skipping!")


# for deduplicating ips
def deduplicate_list(ip_list):
    return list(set(ip_list))


# for only returning duplicates
def duplicates(ip_list):
    # Create an empty dictionary to store the frequency of each element in the list
    counter = {}
    # Create an empty list to store the duplicate elements
    duplicates = []
    # Iterate over each element in the list
    for i in ip_list:
        # If the element is already in the counter dictionary, increment its frequency
        if i in counter:
            counter[i] += 1
        # If the element is not in the counter dictionary, set its frequency to 1
        else:
            counter[i] = 1
    for key, value in counter.items():
        # If the frequency of the current item is greater than 1, add it to the duplicates list
        if value > 1:
            duplicates.append(key)
    return duplicates


def get_ips(a_list, full_a_list, aaaa_list, full_aaaa_list):
    deduplicate_ipv4 = deduplicate_list(a_list)
    deduplicate_ipv6 = deduplicate_list(aaaa_list)
    duplicates_ipv4 = duplicates(a_list)
    duplicates_ipv6 = duplicates(aaaa_list)

    folder_name = "ips"
    create_folders(folder_name)

    # IPV4
    if len(a_list) > 0:

        # Write non-duplicate ipv4 addresses
        with open(f"{folder_name}/{ip_file}", "w") as ip:
            for i in deduplicate_ipv4:
                ip.write(f"{i}\n")

        # Write ipv4 addresses with their hostnames as well (for verifying that the ip actually does belong to an appropriate domain to scan)
        with open(f"{folder_name}/{ip_full_file}", "w") as ip_full:
            for i in full_a_list:
                ip_full.write(f"{i}\n")

    if len(duplicates_ipv4) > 0:
        with open(f"{folder_name}/{vhost_file}", "w") as a:
            for i in duplicates_ipv4:
                a.write(f"{i}\n")

    # IPV6
    if len(aaaa_list) > 0:
        # Write non-duplicate ipv6 addresses
        with open(f"{folder_name}/{ipv6_file}", "w") as ipv6:
            for i in deduplicate_ipv6:
                ipv6.write(f"{i}\n")

        # Write ips with their hostnames as well (for verifying that the ip actually does belong to an appropriate domain to scan)
        with open(f"{folder_name}/{ipv6_full_file}", "w") as ipv6_full:
            for i in full_aaaa_list:
                ipv6_full.write(f"{i}\n")

    if len(duplicates_ipv6) > 0:
        with open(f"{folder_name}/{aaaa_vhost_file}", "w") as aaaa:
            for i in duplicates_ipv6:
                aaaa.write(f"{i}\n")


# Open the input file for reading
with open(input_file, "r") as f:
    # Read the list of domain names from the file
    domains = f.read().splitlines()

# Open the output file for writing
with open(dns_file, "w") as f:
    # Iterate over the list of domain names
    a_records = []
    full_a_records = []
    aaaa_records = []
    full_aaaa_records = []

    for domain in domains:
        # Define a list of DNS record types to query
        output = f"####################\nDomain: {domain}\n####################\n"
        record_types = ["NS", "CNAME", "A", "AAAA", "MX", "SOA", "TXT", "CAA", "HINFO", "AFSDB", "NAPTR", "SRV", ""]
        written_records = set()

        # Iterate over the list of record types
        for record_type in record_types:
            # Use subprocess.run to run the dig command and get the DNS record of the specified type for the domain
            result = subprocess.run(f"dig +noedns +noall +answer {domain} {record_type}", shell=True,
                                    capture_output=True)
            # Get the output from the command
            record = result.stdout.decode()

            # Check that dns record is not empty
            if record != "":
                for dns_record in record.strip().split("\n"):
                    split_record = dns_record.strip().split()
                    filtered_record = f"{split_record[0]}\t{split_record[3]}\t{split_record[4]}"
                    # Add the individual dns record to the set if it's not in there already
                    # print(filtered_record)
                    if filtered_record not in written_records:
                        written_records.add(filtered_record)
                        # Check that the record type is NS
                        if filtered_record.split()[-2] == "NS":
                            nameserver = filtered_record.split()[-1]
                            output += "\n" + tryzonetransfer(domain, nameserver)
                        # If it's an A record, add it to the vhost list
                        if filtered_record.split()[-2] == "A":
                            a_records.append(filtered_record.split()[-1])
                            full_a_records.append(filtered_record)
                        # If it's an AAAA record, add it to the vhost list
                        if filtered_record.split()[-2] == "AAAA":
                            aaaa_records.append(filtered_record.split()[-1])
                            full_aaaa_records.append(filtered_record)
                        output += "\n" + filtered_record

        # Add to valid subdomain list
        if len(written_records) > 0:
            with open(valid_subdomains_file, "a") as subs:
                subs.write(f"{domain}\n")
            output += "\n_______________________\n"
            f.write(output)
    get_ips(a_records, full_a_records, aaaa_records, full_aaaa_records)
