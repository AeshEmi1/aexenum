#!/usr/bin/env python3

import subprocess
import sys
import re

# Check if the required number of arguments was provided
if len(sys.argv) != 3:
    print("Usage: dns_lookup.py <input_file> <output_file>")
    sys.exit(1)

# Get the input and output file names from the arguments
input_file = sys.argv[1]
output_file = sys.argv[2]


def tryzonetransfer(domain, nameserver):
    try:
        zone_result = subprocess.run(["dig", "AXFR", domain, f"@{nameserver}", "+noall", "+answer"], capture_output=True)
        zone_transfer = zone_result.stdout.decode()
        if zone_transfer != "":
            return f"************Trying zone transfer for: {domain} using {nameserver}\n{zone_transfer}\n_________________________\n"
    except:
        pass
    return ""

# Open the input file for reading
with open(input_file, "r") as f:
    # Read the list of domain names from the file
    domains = f.read().splitlines()

# Open the output file for writing
with open(output_file, "w") as f:
    # Iterate over the list of domain names
    for domain in domains:
        # Define a list of DNS record types to query
        output = f"####################\nDomain: {domain}\n####################\n"
        record_types = ["NS", "A", "AAAA", "CNAME", "MX", "SOA", "TXT", "CAA", "HINFO", "AFSDB", "NAPTR", "PR", "ANY"]
        written_records = set()

        # Iterate over the list of record types
        for record_type in record_types:
            # Use subprocess.run to run the dig command and get the DNS record of the specified type for the domain
            result = subprocess.run(["dig", "@8.8.8.8", "+noedns", "+noall", "+answer", record_type, domain], capture_output=True)

            # Get the output from the command
            record = result.stdout.decode()
      
            #Check that record is not empty
            if record != "":
		        #Get each line from the dig result
                for dns_record in record.strip().split("\n"):
                    #Add the individual dns record to the set if it's not in there already
                    if dns_record not in written_records:
                        print(dns_record)
                        written_records.add(dns_record)
				        #Check that the record type is NS
                        if dns_record.strip().split()[-2] == "NS":
                            nameserver = record.strip().split()[-1]
                            output += "\n" + tryzonetransfer(domain, nameserver)
                        output += "\n" + dns_record
        output += "\n_______________________\n"
        f.write(output)
