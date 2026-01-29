#!/usr/bin/env python3

# Python script used to check if an ASN is on a known malicious ASN list and output the results to the console
# Created by HaircutFish aka Dan R. 2025-10-29
# Latest Update 2026-01-27

import argparse
import re
import requests
import sys

parser = argparse.ArgumentParser(
    prog = 'Bad ASN Checker',
    description = 'Provide the a ASN (Autonomous System Number) number in the command line, and the script will search lists of known maliciously (ISP) Internet Service Providers.  Then output the results to the console',
    epilog = 'Test all things, examine everything carefully, and to hold fast that which is good, genuine, and true.',
    add_help=True)

parser.add_argument('-i', '--ip', help='IP Address')

args = parser.parse_args()

asn_info = ""

brianhama_list = requests.get('https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/bad-asn-list.csv')

spamhaus_list = requests.get('https://www.spamhaus.org/drop/asndrop.json')

nullifiedcode_list = requests.get('https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/refs/heads/main/all.txt')

def asn_retrieval_from_ip(ip_address):
    # Calling global variable
    global asn_info

    # Get information from ipinfo
    ip_info = requests.get(f'https://ipinfo.io/{ip_address}/json')

    # Using Regex to get ASN name and number
    asn_from_ip = re.findall('"AS[0-9]{1,6} .*"', ip_info.text)

    # Adding ASN information to global variable
    asn_info = str(*asn_from_ip).replace('"','')

    # Using Regex to pull just the ASN number
    asn = re.findall('[0-9]{1,6}', asn_info)

    # Pulling ASN number from list to string
    if not asn:
        print(f'No ASN information for {ip_address}. Could be an internal IP Address or entered incorrectly.')
        sys.exit(1)
    else:
        return asn

def brianhama_query(asn_num):
    # Create regex query number            
    brianhama_regex_query = f'\\n"?{asn_num[0]}(",|,").*"'

    # Search the bad asn list using the ASN number to see if it appears
    regex_results = re.search(brianhama_regex_query, brianhama_list.text)
    
    # Return the results
    if not regex_results:
        brianhama_results = 'Not on List'
        return brianhama_results
    else:
        brianhama_results = "Considered Malicious"
        return brianhama_results

def spamhaus_query(asn_num):
    # Create regex query number            
    spamhaus_regex_query = f'"asn":{asn_num[0]},"rir":.*'
    
    # Search the bad asn list using the ASN number to see if it appears
    regex_results = re.search(spamhaus_regex_query, spamhaus_list.text)
    
    # Return the results
    if not regex_results:
        spamhaus_results = "Not on List"
        return spamhaus_results
    else:
        spamhaus_results = "Considered Malicious"
        return spamhaus_results

def nullifiedcode_query(asn_num):
    # Create regex query number            
    nullifiedcode_regex_query = f'AS{asn_num[0]}'
    
    # Search the bad asn list using the ASN number to see if it appears
    regex_results = re.search(nullifiedcode_regex_query, nullifiedcode_list.text)
    
    # Return the results
    if not regex_results:
        nullifiedcode_results = "Not on List"
        return nullifiedcode_results
    else:
        nullifiedcode_results = "Considered Malicious"
        return nullifiedcode_results

print ("""
      =================================
      ||    ***Bad ASN Checker***    ||
      =================================""")

if args.ip:
    asn_num = asn_retrieval_from_ip(args.ip)

else:
    parser.print_help()
    sys.exit(1)
 
# Check ASN Lists
brianhama = brianhama_query(asn_num)
spamhaus = spamhaus_query(asn_num)
nullifiedcode = nullifiedcode_query(asn_num) 
print(f'ASN Name            : {asn_info}')
print(f'brianhama List      : {brianhama}')
print(f'Spamhaus List       : {spamhaus}')
print(f'NullifiedCode List  : {nullifiedcode}')
sys.exit(1)