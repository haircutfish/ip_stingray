import os
import re
import sys
import time
import requests

from .config import LISTS, CACHE_EXPIRY_SECONDS

def get_list_content(list_key):
    info = LISTS[list_key]
    file_path = info['file']
    url = info['url']
    
    needs_update = True
    if os.path.exists(file_path):
        file_age = time.time() - os.path.getmtime(file_path)
        if file_age < CACHE_EXPIRY_SECONDS:
            needs_update = False
            
    if needs_update:
        try:
            print(f"Updating local copy of {list_key} list...")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
        except requests.exceptions.Timeout:
            print(f"Warning: The connection timed out while updating the {list_key} list.")
            if not os.path.exists(file_path):
                print(f"Error: No local copy of {list_key} list available.")
                sys.exit(1)
        except Exception as e:
            print(f"Warning: Failed to update {list_key} list: {e}")
            if not os.path.exists(file_path):
                print(f"Error: No local copy of {list_key} list available.")
                sys.exit(1)
                
    asn_set = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if list_key == 'brianhama':
                    parts = line.split(',', 1)
                    if parts and parts[0].isdigit():
                        asn_set.add(parts[0])
                elif list_key == 'spamhaus':
                    match = re.search(r'"asn":\s*(\d+)', line)
                    if match:
                        asn_set.add(match.group(1))
                elif list_key == 'nullifiedcode':
                    if line.startswith('AS'):
                        parts = line.split(' ', 1)
                        asn_str = parts[0][2:]
                        if asn_str.isdigit():
                            asn_set.add(asn_str)
    except Exception as e:
        print(f"Error reading {list_key} list: {e}")
        
    return asn_set

def get_all_lists():
    brianhama_set = get_list_content('brianhama')
    spamhaus_set = get_list_content('spamhaus')
    nullifiedcode_set = get_list_content('nullifiedcode')
    return brianhama_set, spamhaus_set, nullifiedcode_set

def brianhama_query(asn_num, brianhama_set):
    return "Considered Malicious" if asn_num[0] in brianhama_set else "Not on List"

def spamhaus_query(asn_num, spamhaus_set):
    return "Considered Malicious" if asn_num[0] in spamhaus_set else "Not on List"

def nullifiedcode_query(asn_num, nullifiedcode_set):
    return "Considered Malicious" if asn_num[0] in nullifiedcode_set else "Not on List"
