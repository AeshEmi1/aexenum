# AexEnum

Aexenum is a tool that automates the discovery and enumeration of subdomains, nameservers, vhosts, and WAFs. It uses subfinder and gobuster to perform the subdomain enumeration, it uses dig to find DNS record information, it uses wafw00f to scan for WAFs, and it uses whois, whatweb, and waybackurls to look for other potentially juicy information. 

## Prerequisites

Before you begin, ensure you have the following installed:

* python3
* dig
* whois
* subfinder
* gobuster
* whatweb
* wafw00f
* waybackurls
* dns-info.py (provided in repository)

## Usage

    python3 aexenum.py <domains_file> <wordlist> <common_file_name> [options]

### Options
    
    domains_file          File containing a list of in-scope domains
    wordlist              Wordlist to use with gobuster for subdomain enumeration
    common_name           Common name to use for output files
    -h, --help            show the help message
    -v, --verbose         Enable verbosity
    -a, --all             Run additional gobuster instances with the found root name servers
    -s, --shutdown        Shutdown system when complete
    --delete              Delete individual subfinder and and gobuster files after they are merged
