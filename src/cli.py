import argparse
import sys
import ipaddress
import json
from colorama import Fore, Style, init

from .api import asn_retrieval_from_ip
from . import config
from . import domain_checker
from . import scoring
from .threat_lists import (
    get_all_lists,
    brianhama_query,
    spamhaus_query,
    nullifiedcode_query
)

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(
        prog = 'IP Stingray',
        description = 'A Python script for evaluating the threat level of an IP address or domain. Scoring Ranges: Low Risk (<21), Suspicious (21-50), High Risk (51-84), Very High Risk (>=85).',
        epilog = 'Test all things, examine everything carefully, and to hold fast that which is good, genuine, and true.',
        add_help=True)

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('-i', '--ip', help='IP Address')
    target_group.add_argument('-d', '--domain', help='Domain Name')
    target_group.add_argument('--set-api-key', help='Save your ipapi.is API key securely to bypass rate limits.')

    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--scoring', action='store_true', help='Show threat score ranges and exit.')

    args = parser.parse_args()
    
    if args.scoring:
        print("""
Threat Score Ranges:
  - Low Risk      : < 21 points
  - Suspicious    : 21 - 50 points
  - High Risk     : 51 - 84 points
  - Very High Risk: >= 85 points
""")
        sys.exit(0)
        
    if args.set_api_key:
        config.save_api_key(args.set_api_key)
        print(f"Successfully saved API key to {config.API_KEY_FILE}")
        sys.exit(0)
    
    domain_intel = None
    if args.domain:
        resolved_ip = domain_checker.get_ip_from_domain(args.domain)
        if not resolved_ip:
            print(f"Error: Could not resolve domain '{args.domain}'.")
            sys.exit(1)
        
        domain_intel = domain_checker.get_domain_intelligence(args.domain)
        
        args.ip = resolved_ip

    if args.ip:
        try:
            ipaddress.ip_address(args.ip)
        except ValueError:
            print(f"Error: '{args.ip}' is not a valid IP address.")
            sys.exit(1)
            
        api_key = config.load_api_key()
        asn_num, asn_info, ip_intelligence_data = asn_retrieval_from_ip(args.ip, api_key=api_key)
    else:
        parser.print_help()
        sys.exit(1)

    brianhama_set, spamhaus_set, nullifiedcode_set = get_all_lists()

    brianhama = brianhama_query(asn_num, brianhama_set)
    spamhaus = spamhaus_query(asn_num, spamhaus_set)
    nullifiedcode = nullifiedcode_query(asn_num, nullifiedcode_set) 

    threat_score, threat_level = scoring.calculate_score(
        ip_intelligence_data, brianhama, spamhaus, nullifiedcode, domain_intel
    )
    
    ip_intelligence_data['overall_threat_level'] = threat_level

    if args.json:
        output = {
            "ip": args.ip,
            "asn_info": asn_info,
            "ip_intelligence": ip_intelligence_data,
            "threat_lists": {
                "brian_hama": brianhama,
                "spamhaus": spamhaus,
                "nullified_code": nullifiedcode
            },
            "overall_threat_score": threat_score,
            "overall_threat_level": threat_level
        }
        if domain_intel:
            output["domain_intelligence"] = domain_intel
        print(json.dumps(output, indent=4))
        sys.exit(0)

    print ("""
      =================================
      ||      ***IP Stingray***     ||
      =================================""")

    if domain_intel:
        print('\n' + ' Domain Intelligence '.center(40, '-'))
        whois = domain_intel['whois']
        dns = domain_intel['dns']
        print(f"Creation date       : {whois.get('creation_date')}")
        print(f"Expiration date     : {whois.get('expiration_date')}")
        print(f"Updated date        : {whois.get('updated_date')}")
        print(f"Domain Age          : {domain_intel.get('age_description')}")
        print(f"Domain Age Risk     : {domain_intel.get('age_risk')}")
        print(f"A Record            : {dns.get('A')}")
        print(f"AAAA Record         : {dns.get('AAAA')}")
        print(f"NS Record           : {dns.get('NS')}")
        print(f"MX Record           : {dns.get('MX')}")
        print(f"TXT Record          : {dns.get('TXT')}")
        print(f"Site Headers        : {domain_intel.get('curl')}")

    print('\n' + ' IP Intelligence '.center(40, '-'))
    print(f"Company Name        : {ip_intelligence_data.get('company_name')}")
    print(f"Company Abuse Score : {ip_intelligence_data.get('company_abuser_score')}")   
    print(f'ASN                 : {asn_info}')
    print(f"ASN Abuse Score     : {ip_intelligence_data.get('asn_abuser_score')}")
    print(f"Location            : {ip_intelligence_data.get('location')}")
    print(f"Datacenter          : {ip_intelligence_data.get('is_datacenter')}")
    print(f"Proxy               : {ip_intelligence_data.get('is_proxy')}")
    print(f"VPN                 : {ip_intelligence_data.get('is_vpn')}")
    print(f"Abuser              : {ip_intelligence_data.get('is_abuser')}")

    print('\n' + ' Threat List Checks '.center(40, '-'))
    print(f'Brian Hama List     : {brianhama}')
    print(f'Spamhaus List       : {spamhaus}')
    print(f'NullifiedCode List  : {nullifiedcode}')

    print('\n' + ' Evaluation '.center(40, '-'))
    
    if threat_level in ["Very High Risk", "High Risk"]:
        color = Fore.RED
    elif threat_level == "Suspicious":
        color = Fore.YELLOW
    else:
        color = Fore.GREEN
        
    print(f'Overall Threat Score: {color}{Style.BRIGHT}{threat_level} ({threat_score} points)')
    sys.exit(0)
