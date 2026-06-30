import os
import stat
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR, exist_ok=True)

LISTS = {
    'brianhama': {
        'url': 'https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/bad-asn-list.csv',
        'file': os.path.join(DATA_DIR, 'brianhama_list.csv')
    },
    'spamhaus': {
        'url': 'https://www.spamhaus.org/drop/asndrop.json',
        'file': os.path.join(DATA_DIR, 'spamhaus_list.jsonl')
    },
    'nullifiedcode': {
        'url': 'https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/refs/heads/main/all.txt',
        'file': os.path.join(DATA_DIR, 'nullifiedcode_list.txt')
    }
}

CACHE_EXPIRY_SECONDS = 7 * 24 * 60 * 60

CONFIG_DIR = Path.home() / '.ip_stingray'
API_KEY_FILE = CONFIG_DIR / 'api_key'

def save_api_key(key):
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    API_KEY_FILE.write_text(key.strip())
    API_KEY_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)

def load_api_key():
    env_key = os.environ.get('IPAPI_KEY')
    if env_key:
        return env_key.strip()
        
    if API_KEY_FILE.exists():
        return API_KEY_FILE.read_text().strip()
    return None
