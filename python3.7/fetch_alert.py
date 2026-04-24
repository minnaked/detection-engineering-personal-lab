import requests
import json
import urllib3

# Disable security warnings for self-signed certs (Standard for Home Labs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION (The "Keys" to the Kingdom) ---
WAZUH_IP = "192.168.1.12"  # Your Intel OVA IP
USER = "admin"             # Default User
PASS = "admin" # Default Password
# We query the 'Indexer' directly because that's where logs live
URL = f"https://{WAZUH_IP}:9200/wazuh-alerts-*/_search"

# --- THE QUERY (Logic: Find the exact alert we created) ---
# We look for Rule ID 100004 (Your Sysmon Termination Rule)
query = {
    "size": 1,  # Get only the latest one
    "sort": [{"@timestamp": "desc"}], # Newest first
    "query": {
        "match": {
            "rule.id": "100003" 
        }
    }
}

print(f"[+] Connecting to Wazuh Brain at {WAZUH_IP}...")

try:
    # 1. THE HANDSHAKE (Basic Auth)
    response = requests.get(
        URL, 
        auth=(USER, PASS), 
        json=query, 
        verify=False # Ignore SSL errors
    )

    # 2. THE CHECK
    if response.status_code == 200:
        data = response.json()
        hits = data['hits']['hits']
        
        if len(hits) > 0:
            # 3. THE EXTRACTION (Parsing the Real Log)
            log_source = hits[0]['_source']
            timestamp = log_source['@timestamp']
            agent_name = log_source['agent']['name']
            
            # Extracting the specific fields you care about
            # Note: Field names depend on your specific Wazuh version structure
            # We use .get() to avoid crashing if a field is missing
            process = log_source['data']['win']['eventdata'].get('image', 'Unknown')
            user = log_source['data']['win']['eventdata'].get('user', 'Unknown')

            print(f"\n[SUCCESS] Alert Found!")
            print(f"Time:    {timestamp}")
            print(f"Target:  {agent_name}")
            print(f"Process: {process}")
            print(f"User:    {user}")
            
            if "whoami" in process and "vboxuser" in user:
                 print("\n[CRITICAL] Automated Triage: Confirmed Lab Activity.")
        else:
            print("\n[INFO] No alerts found for Rule 100003. Run 'whoami' again!")
    else:
        print(f"\n[ERROR] Failed to connect. Status Code: {response.status_code}")
        print(f"Reason: {response.text}")

except Exception as e:
    print(f"\n[FATAL] Connection refused. Is Port 9200 open on the Intel VM?")
    print(f"Error details: {e}")
