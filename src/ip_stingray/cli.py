import argparse
import sys
import ipaddress
import json
from colorama import Fore, Style, init

from .api import asn_retrieval_from_ip
from . import config
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
        description = 'A Python script for evaluating the threat level of an IP address. It retrieves IP intelligence data (like VPN/Proxy status and Abuse scores), checks its Autonomous System Number (ASN) against multiple known threat lists, and outputs a combined Overall Threat Score.',
        epilog = 'Test all things, examine everything carefully, and to hold fast that which is good, genuine, and true.',
        add_help=True)

    parser.add_argument('-i', '--ip', help='IP Address')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--set-api-key', help='Save your ipapi.is API key securely to bypass rate limits.')

    args = parser.parse_args()
    
    if args.set_api_key:
        config.save_api_key(args.set_api_key)
        print(f"Successfully saved API key to {config.API_KEY_FILE}")
        sys.exit(0)
    
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

    # Fetch sets from local cache (updating if necessary)
    brianhama_set, spamhaus_set, nullifiedcode_set = get_all_lists()

    # Check ASN Lists
    brianhama = brianhama_query(asn_num, brianhama_set)
    spamhaus = spamhaus_query(asn_num, spamhaus_set)
    nullifiedcode = nullifiedcode_query(asn_num, nullifiedcode_set) 

    threat_level = ip_intelligence_data.get('overall_threat_level')
    if "Considered Malicious" in [brianhama, spamhaus, nullifiedcode]:
        if threat_level == "Low Risk":
            threat_level = "Suspicious"
        elif threat_level == "Suspicious":
            threat_level = "High Risk"
        elif threat_level == "High Risk":
            threat_level = "Very High Risk"

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
            "overall_threat_score": threat_level
        }
        print(json.dumps(output, indent=4))
        sys.exit(0)

    print ("""
      =================================
      ||      ***IP Stingray***     ||
      =================================""")

    print('\n' + ' IP Intelligence '.center(40, '-'))
    print(f'ASN                 : {asn_info}')
    print(f"Location            : {ip_intelligence_data.get('location')}")
    print(f"Datacenter          : {ip_intelligence_data.get('is_datacenter')}")
    print(f"Proxy               : {ip_intelligence_data.get('is_proxy')}")
    print(f"VPN                 : {ip_intelligence_data.get('is_vpn')}")
    print(f"Abuser              : {ip_intelligence_data.get('is_abuser')}")
    print(f"Company Abuse Score : {ip_intelligence_data.get('company_abuser_score')}")
    print(f"ASN Abuse Score     : {ip_intelligence_data.get('asn_abuser_score')}")

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
        
    print(f'Overall Threat Score: {color}{Style.BRIGHT}{threat_level}')
    sys.exit(0)

if __name__ == "__main__":
    main()
