import sys
import requests

def asn_retrieval_from_ip(ip_address, api_key=None):
    try:
        url = f'https://api.ipapi.is/?q={ip_address}'
        if api_key:
            url += f'&key={api_key}'
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        print(f"Error: The connection timed out while retrieving information for {ip_address}.")
        sys.exit(1)
    except Exception as e:
        print(f"Error retrieving information for {ip_address}: {e}")
        sys.exit(1)

    if not data or 'ip' not in data:
        print(f'No valid information found for {ip_address}. Could be an internal IP Address or entered incorrectly.')
        sys.exit(1)

    vpn_dict = data.get('vpn',{})
    vpn_service = vpn_dict.get('service', 'Unknown')

    company_dict = data.get('company', {})
    company_name = company_dict.get('name', 'Unknown')
    company_score = str(company_dict.get('abuser_score', 'Unknown'))

    asn_dict = data.get('asn', {})
    asn_number = asn_dict.get('asn')
    asn_org = asn_dict.get('org', 'Unknown')

    location = data.get('location', {})
    city = location.get('city', 'Unknown')
    state = location.get('state', 'Unknown')
    country = location.get('country', 'Unknown')
    
    if not asn_number:
        print(f'No ASN information for {ip_address}. Could be an internal IP Address or entered incorrectly.')
        sys.exit(1)

    asn_score = str(asn_dict.get('abuser_score', 'Unknown'))
    is_abuser_bool = bool(data.get('is_abuser', False))
    
    threat_level = "Low Risk"
    if 'Very High' in company_score or 'Very High' in asn_score:
        threat_level = "Very High Risk"
    elif is_abuser_bool or 'High' in company_score or 'High' in asn_score:
        threat_level = "High Risk"
    elif 'Elevated' in company_score or 'Elevated' in asn_score:
        threat_level = "Suspicious"

    ip_intelligence_data = {
        'location': f"{city}, {state}, {country}",
        'is_datacenter': "Yes" if data.get('is_datacenter') else "No",
        'is_proxy': "Yes" if data.get('is_proxy') else "No",
        'is_vpn': vpn_service if vpn_service != 'Unknown' else "No",
        'is_abuser': "Yes" if is_abuser_bool else "No",
        'company_abuser_score': company_score,
        'asn_abuser_score': asn_score,
        'overall_threat_level': threat_level,
        'company_name': company_name
    }

    asn_info = f"AS{asn_number} {asn_org}"
    
    return [str(asn_number)], asn_info, ip_intelligence_data
