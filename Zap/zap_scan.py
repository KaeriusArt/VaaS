import os
import shutil
import subprocess
import argparse
from datetime import datetime

def run_zap_scan(target, index):
    zap_dir = "/home/ubuntu1/VaaS/Zap"
    reports_dir = "/home/ubuntu1/VaaS/_Reports"
    
    cleaned_target = target.replace("https://", "").replace("http://", "")
    current_date = datetime.now().strftime("%Y%m%d")
    report_name = f"{index}_zap_{current_date}"

    json_report_path = f"/zap/wrk/{report_name}.json"
    local_report_path = os.path.join(zap_dir, f"{report_name}.json")
    destination_path = os.path.join(reports_dir, f"{report_name}.json")
    
    # Docker command
    docker_command = [
        "docker", "run", "--rm",
        "-v", f"{zap_dir}:/zap/wrk/:rw",
        "-t", "ghcr.io/zaproxy/zaproxy:stable",
        "zap-full-scan.py",
        "-t", target,
        "-g", "/zap/wrk/gen.conf",
        "-J", json_report_path,
        "-d"
    ]
    
    command = ' '.join(docker_command)
    print(command)
    print(f"Running ZAP scan for target: {target} with index: {index}")
    subprocess.run(docker_command, check=False)
    print("ZAP scan complete.")
    
    if os.path.isfile(local_report_path):
        print(f"Report found: {local_report_path}")
        
        shutil.move(local_report_path, destination_path)
        print(f"Report moved to: {destination_path}")
    else:
        print(f"No report found at {local_report_path}.")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="ZAP Scan Automation with Docker")
    parser.add_argument(
        "--target", type=str, required=True,
        help="Target IP Address or website for the VAPT scan (must start with 'http://' or 'https://')"
    )
    parser.add_argument(
        "--index", type=str, required=True,
        help="Index of the Queued Task"
    )
    
    args = parser.parse_args()
    run_zap_scan(args.target, args.index)
