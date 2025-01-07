import requests
import time
import urllib3
import re
import argparse
from datetime import datetime
import subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

host = "https://192.168.100.2"

def get_headers():
    time.sleep(2)
    url = f"{host}:8834/nessus6.js?v=1725650918429"
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        js_code = response.text
        match = re.search(r'getApiToken.*?return"([a-fA-F0-9\-]+)"', js_code)
        if match:
            api_token = match.group(1)
        else:
            print("API token not found in the JavaScript code.")
    else:
        print(f"Failed to fetch the JavaScript file. Status code: {response.status_code}")
    time.sleep(2)
    url = f"{host}:8834/session"
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
def export_scan(scan_id, headers_t, format="csv", base_url=f"{host}:8834"):
    url = f"{base_url}/scans/{scan_id}/export?limit=2500"
    headers = {
        "X-API-Token": headers_t.get("X-API-Token"),
        "X-Cookie": headers_t.get("X-Cookie"),
    }

    data = {
        "format": "csv",
        "template_id": "",
        "reportContents": {
            "csvColumns": {
                "id": False,
                "cve": False,
                "cvss": False,
                "risk": True,
                "hostname": True,
                "protocol": False,
                "port": False,
                "plugin_name": True,
                "synopsis": False,
                "description": False,
                "solution": True,
                "see_also": False,
                "plugin_output": False,
                "stig_severity": False,
                "cvss4_base_score": False,
                "cvss4_bt_score": False,
                "cvss3_base_score": False,
                "cvss_temporal_score": False,
                "cvss3_temporal_score": False,
                "vpr_score": False,
                "epss_score": False,
                "risk_factor": False,
                "references": False,
                "plugin_information": False,
                "exploitable_with": False
            }
        },
        "extraFilters": {
            "host_ids": [],
            "plugin_ids": []
        },
        "plugin_detail_locale": "en"
    }

    session = requests.Session()
    request = requests.Request("POST", url, headers=headers, json=data)
    prepared_request = session.prepare_request(request)
    response = session.send(prepared_request, verify=False)
    if response.status_code == 200:
        return response.json().get('token')
    else:
        response.raise_for_status()
        
def download_file(token_id, destination_path, base_url=f"{host}:8834"):
    url = f"{base_url}/tokens/{token_id}/download"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1"
    }
    response = requests.get(url, headers=headers, verify=False, stream=True)

    if response.status_code == 200:
        with open(destination_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print(f"CSV saved to {destination_path}")
    else:
        print(f"Failed to download file: {response.status_code}")
        response.raise_for_status()
def main(target_system,filepath):
    url = f"{host}:8834/scans"
    Results_filepath = filepath
    data = {
        "uuid": "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65",
        "credentials": {
            "add": {},
            "edit": {},
            "delete": []
        },
        "settings": {
            "patch_audit_over_telnet": "no",
            "patch_audit_over_rsh": "no",
            "patch_audit_over_rexec": "no",
            "snmp_port": "161",
            "additional_snmp_port1": "161",
            "additional_snmp_port2": "161",
            "additional_snmp_port3": "161",
            "http_login_method": "POST",
            "http_reauth_delay": "",
            "http_login_max_redir": "0",
            "http_login_invert_auth_regex": "no",
            "http_login_auth_regex_on_headers": "no",
            "http_login_auth_regex_nocase": "no",
            "never_send_win_creds_in_the_clear": "yes",
            "dont_use_ntlmv1": "yes",
            "start_remote_registry": "no",
            "enable_admin_shares": "no",
            "start_server_service": "no",
            "ssh_known_hosts": "",
            "ssh_port": "22",
            "ssh_client_banner": "OpenSSH_5.0",
            "attempt_least_privilege": "no",
            "vendor_unpatched": "no",
            "log_whole_attack": "no",
            "always_report_ssh_cmds": "no",
            "enable_plugin_debugging": "no",
            "debug_level": "1",
            "enable_plugin_list": "no",
            "audit_trail": "use_scanner_default",
            "include_kb": "use_scanner_default",
            "windows_search_filepath_exclusions": "",
            "windows_search_filepath_inclusions": "",
            "custom_find_filepath_exclusions": "",
            "custom_find_filesystem_exclusions": "",
            "custom_find_filepath_inclusions": "",
            "custom_find_timeout": "",
            "reduce_connections_on_congestion": "no",
            "network_receive_timeout": "5",
            "max_checks_per_host": "5",
            "max_hosts_per_scan": "30",
            "max_simult_tcp_sessions_per_host": "",
            "max_simult_tcp_sessions_per_scan": "",
            "safe_checks": "yes",
            "stop_scan_on_disconnect": "no",
            "slice_network_addresses": "no",
            "auto_accept_disclaimer": "no",
            "scan.allow_multi_target": "no",
            "host_tagging": "yes",
            "trusted_cas": "",
            "advanced_mode": "Default",
            "allow_post_scan_editing": "yes",
            "reverse_lookup": "no",
            "log_live_hosts": "no",
            "display_unreachable_hosts": "no",
            "display_unicode_characters": "no",
            "report_verbosity": "Normal",
            "report_superseded_patches": "yes",
            "silent_dependencies": "yes",
            "oracle_database_use_detected_sids": "no",
            "samr_enumeration": "yes",
            "adsi_query": "yes",
            "wmi_query": "yes",
            "rid_brute_forcing": "no",
            "request_windows_domain_info": "no",
            "scan_webapps": "no",
            "user_agent_string": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)",
            "test_default_oracle_accounts": "no",
            "provided_creds_only": "yes",
            "report_paranoia": "Normal",
            "thorough_tests": "no",
            "assessment_mode": "default",
            "collect_identity_data_from_ad": "",
            "svc_detection_on_all_ports": "yes",
            "detect_ssl": "yes",
            "ssl_prob_ports": "All ports",
            "dtls_prob_ports": "None",
            "cert_expiry_warning_days": "60",
            "enumerate_all_ciphers": "yes",
            "check_crl": "no",
            "tcp_scanner": "no",
            "tcp_firewall_detection": "Automatic (normal)",
            "syn_scanner": "yes",
            "syn_firewall_detection": "Automatic (normal)",
            "udp_scanner": "no",
            "ssh_netstat_scanner": "yes",
            "wmi_netstat_scanner": "yes",
            "snmp_scanner": "yes",
            "only_portscan_if_enum_failed": "yes",
            "verify_open_ports": "no",
            "unscanned_closed": "no",
            "portscan_range": "default",
            "wol_mac_addresses": "",
            "wol_wait_time": "5",
            "scan_network_printers": "no",
            "scan_netware_hosts": "no",
            "scan_ot_devices": "no",
            "ping_the_remote_host": "yes",
            "arp_ping": "yes",
            "tcp_ping": "yes",
            "tcp_ping_dest_ports": "built-in",
            "icmp_ping": "yes",
            "icmp_unreach_means_host_down": "no",
            "icmp_ping_retries": "2",
            "udp_ping": "no",
            "test_local_nessus_host": "yes",
            "fast_network_discovery": "no",
            "discovery_mode": "Port scan (common ports)",
            "emails": "",
            "filter_type": "and",
            "filters": [],
            "launch_now": True,
            "enabled": True,
            "name": f"{target_system} {cur_datetime}",
            "description": "",
            "folder_id": 3,
            "scanner_id": "1",
            "text_targets": target_system,
            "file_targets": ""
        }
    }

    response = requests.post(url, headers=get_headers(), json=data, verify=False)

    try:
        scan_id = response.json().get('scan', {}).get('id')
    except ValueError:
        print(response.text)


    while True:
        url = f"{host}:8834/scans/{scan_id}?"
        while True:
            try:    
                response = requests.get(url, headers=get_headers(), verify=False)
                data = response.json()
                target = data.get("info", {}).get("targets")
                status = data.get("info", {}).get("status")
                scan_progress_current = data.get("hosts", [{}])[0].get("scanprogresscurrent")
                break
            except:
                print(f"No Host Found Please Wait......{status}")
                time.sleep(30)
                continue
        print(f"\r{target} {status} {scan_progress_current}%          ", end="")
        if status == "completed":
            print("\nScan is complete. Generating CSV file....")
            download_file(export_scan(scan_id,get_headers()), Results_filepath)
            time.sleep(5)
            delete_task(scan_id)
            break  
        time.sleep(5)
        
def delete_task(scan_id):
    url = f"{host}:8834/scans"
    data = {
    "ids": [scan_id]
    }
    response = requests.delete(url, headers=get_headers(), json=data, verify=False)
    if response.status_code == 200:
        print(f"Scan ID {scan_id} has been successfully deleted.")
    else:
        print(f"Failed to delete scan ID {scan_id}. Status Code: {response.status_code}, Response: {response.text}")

def check_status():
    url = f"{host}:8834/server/status"
    try:
        response = requests.get(url, verify=False)
        data = response.json()
        status = data.get("status", "unknown")
        print(f"The feed status is: {status}")
        return status == "ready"
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return False 

def update_feed():
    url = f"{host}:8834/settings/software-update"    
    try:
        response = requests.post(url, headers=get_headers(), verify=False)
        if response.status_code == 200:
            print("Software Update Ongoing....")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def wait_feed_status():
    print("Waiting for updates to reflect...")
    while not check_status():
        print("Feeds are still not updated. Checking again in 30 seconds...")
        time.sleep(30)
    print("Feeds are now up-to-date.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nessus Scan Script")
    parser.add_argument("--target", type=str, required=True, help="Target IP Address or website for the VAPT scan (must start with 'http://' or 'https://')")
    parser.add_argument("--index", type=str, required=True, help="Index of the Queued Task")
    args = parser.parse_args()
    # bypaz()
    target = args.target
    
    cleaned_target = target.replace("https://", "").replace("http://", "")
    cur_datetime = datetime.now().strftime("%Y%m%d")
    filepath = f'/home/ubuntu1/VaaS/_Reports/{args.index}_nessus_{cur_datetime}.csv'

    print(f"The queued index '{args.index}' is now under Nessus.")
    update_feed()
    if check_status():
        print("All feeds are up-to-date. Proceeding to VAPT scan...")
        main(cleaned_target,filepath)
    else:
        update_feed()
        wait_feed_status()
        main(cleaned_target,filepath)
    








