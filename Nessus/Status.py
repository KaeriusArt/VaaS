import requests
import time
import urllib3
import re
import argparse
from datetime import datetime
import subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
host = "192.168.100.2"
def get_headers():
    time.sleep(2)
    url = f"https://{host}:8834/nessus6.js?v=1725650918429"
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        js_code = response.text
        match = re.search(r'key:"getApiToken",value:function\(\){return"([a-f0-9\-]+)"}', js_code)
        if match:
            api_token = match.group(1)
        else:
            print("API token not found in the JavaScript code.")
    else:
        print(f"Failed to fetch the JavaScript file. Status code: {response.status_code}")
    time.sleep(2)
    url = f"https://{host}:8834/session"
    headers = {"X-API-Token": api_token}
    data = {"username": "admin","password": "admin1234"} #palitan mo to bases sa registration mo
    response = requests.post(url, headers=headers, json=data, verify=False) 
    try:
        token = response.json().get("token")
        token = "token="+token
    except ValueError:
        print("Error:", response.status_code, response.text) 

    headers = {
        "X-API-Token": api_token,
        "X-Cookie": token,
    }
    time.sleep(1)
    return headers


url = "https://192.168.153.200:8834/settings/software-update"    
try:
    response = requests.post(url, headers=get_headers(), verify=False)
    if response.status_code == 200:
        print("Software Update Ongoing....")

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")