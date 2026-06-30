def calculate_score(ip_intel: dict, brianhama: str, spamhaus: str, nullifiedcode: str, domain_intel: dict = None) -> tuple:
    score = 0
    
    if ip_intel.get('is_abuser') == "Yes":
        score += 40
    if ip_intel.get('is_proxy') == "Yes":
        score += 30
    if ip_intel.get('is_vpn') != "No":
        score += 15
    if ip_intel.get('is_datacenter') == "Yes":
        score += 10
    if ip_intel.get('company_name') in ['Google LLC', 'Microsoft Corporation']:
        score -= 40
        
    def get_score_points(score_str):
        if not score_str:
            return 0
        if "Very High" in score_str:
            return 40
        if "High" in score_str:
            return 25
        if "Elevated" in score_str:
            return 15
        return 0
        
    score += get_score_points(ip_intel.get('company_abuser_score', ''))
    score += get_score_points(ip_intel.get('asn_abuser_score', ''))
    
    if spamhaus == "Considered Malicious":
        score += 40
    if brianhama == "Considered Malicious":
        score += 30
    if nullifiedcode == "Considered Malicious":
        score += 30
        
    if domain_intel:
        age_risk = domain_intel.get('age_risk')
        if age_risk == "Very High Risk":
            score += 40
        elif age_risk == "High Risk":
            score += 25
        elif age_risk == "Suspicious":
            score += 15
        elif age_risk == "Low Risk":
            score += 0
        elif age_risk == "Unknown":
            score += 0
            
    if score >= 85:
        level = "Very High Risk"
    elif score >= 51:
        level = "High Risk"
    elif score >= 21:
        level = "Suspicious"
    else:
        level = "Low Risk"
        
    return score, level
