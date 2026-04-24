import json

# This matches the Sysmon Event ID 5 log you generated (Process Terminate)
raw_log = """
{
    "win": {
        "system": {
            "eventID": "5",
            "computer": "windows11Detect"
        },
        "eventdata": {
            "image": "C:\\\\Windows\\\\System32\\\\whoami.exe",
            "user": "WINDOWS11DETECT\\\\vboxuser"
        }
    }
}
"""

# 1. Parse the Raw Text into Data
data = json.loads(raw_log)

# 2. The "Detection Logic" (This is what you get paid for)
process_name = data['win']['eventdata']['image']
user_account = data['win']['eventdata']['user']

print(f"Analyzing Log...")
print(f"Process Found: {process_name}")
print(f"User Found:    {user_account}")

# 3. The Alert Trigger
if "whoami.exe" in process_name and "vboxuser" in user_account:
    print("\n[CRITICAL ALERT] Reconnaissance detected by a Lab User!")
else:
    print("\n[INFO] Benign activity.")
