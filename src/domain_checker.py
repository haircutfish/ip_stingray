import socket
import whois21
import dns.resolver
import requests
import concurrent.futures
from datetime import datetime, timezone

def get_ip_from_domain(domain: str) -> str:
    """
    Resolves a domain name to an IPv4 address.
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def query_dns(domain: str, record_type: str) -> str:
    """
    Queries DNS for a specific record type using dnspython.
    """
    try:
        # Use a custom resolver with a timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(domain, record_type)
        return ", ".join([str(rdata) for rdata in answers])
    except Exception:
        return "No Results Found"

def get_http_headers(domain: str) -> str:
    """
    Retrieves HTTP headers for a domain using requests.
    """
    try:
        # Try HTTPS first, then fallback to HTTP
        for protocol in ["https://", "http://"]:
            try:
                response = requests.head(f"{protocol}{domain}", timeout=3, allow_redirects=True)
                version = "1.1" # Requests doesn't easily expose the HTTP version string like 'HTTP/1.1'
                return f"HTTP/{version} {response.status_code} {response.reason}"
            except requests.RequestException:
                continue
        return "No HTTP headers found"
    except Exception:
        return "Error retrieving headers"

def calculate_domain_risk(creation_date) -> tuple:
    """
    Calculates domain risk based on age.
    Returns (risk_level, age_description).
    """
    if not creation_date or creation_date == "Unknown":
        return "Unknown", "Unknown"
    
    try:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if isinstance(creation_date, str):
            return "Unknown", "Unknown"

        now = datetime.now(timezone.utc)
        age = now - creation_date
        days = age.days
        months = days / 30.44
        
        # Risk Categories:
        # < 6 months: Very High Risk
        # 6-12 months: High Risk
        # 12-18 months: Suspicious
        # > 18 months: Low Risk
        
        if months < 6:
            return "Very High Risk", f"{months:.1f} months"
        elif months < 12:
            return "High Risk", f"{months:.1f} months"
        elif months < 18:
            return "Suspicious", f"{months:.1f} months"
        else:
            return "Low Risk", f"{months:.1f} months"
    except Exception:
        return "Unknown", "Unknown"

def get_domain_intelligence(domain: str) -> dict:
    """
    Gathers intelligence about a domain name in parallel for optimization.
    """
    # Use max_workers to parallelize DNS, WHOIS, and HTTP checks
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit DNS queries
        dns_types = ['A', 'AAAA', 'NS', 'MX', 'TXT']
        dns_futures = {t: executor.submit(query_dns, domain, t) for t in dns_types}
        
        # Submit WHOIS and HTTP header checks
        whois_future = executor.submit(whois21.WHOIS, domain)
        http_future = executor.submit(get_http_headers, domain)
        
        # Collect results with timeouts to prevent hanging
        dns_results = {}
        for t, f in dns_futures.items():
            try:
                dns_results[t] = f.result(timeout=5)
            except concurrent.futures.TimeoutError:
                dns_results[t] = "Timeout"
        
        try:
            whois = whois_future.result(timeout=10)
        except concurrent.futures.TimeoutError:
            whois = None
            
        try:
            http_headers = http_future.result(timeout=5)
        except concurrent.futures.TimeoutError:
            http_headers = "Timeout"

        # Process WHOIS data
        whois_data = {
            'creation_date': "Unknown",
            'expiration_date': "Unknown",
            'updated_date': "Unknown",
            'raw_creation_date': None
        }
        
        if whois and whois.success:
            def format_date(d):
                if isinstance(d, list):
                    return d[0] if d else None
                return d

            raw_created = format_date(whois.creation_date)
            whois_data = {
                'creation_date': str(raw_created) if raw_created else "Unknown",
                'expiration_date': str(format_date(whois.expires_date)) if whois.expires_date else "Unknown",
                'updated_date': str(format_date(whois.updated_date)) if whois.updated_date else "Unknown",
                'raw_creation_date': raw_created
            }
        
        # Calculate risk based on age
        risk_level, age_str = calculate_domain_risk(whois_data['raw_creation_date'])
        
        return {
            'dns': dns_results,
            'whois': whois_data,
            'curl': http_headers,
            'age_risk': risk_level,
            'age_description': age_str
        }
