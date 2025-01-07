import os
import subprocess
import argparse
from datetime import datetime

def run_nikto_scan(target, index):
    reports_dir = "/home/ubuntu1/VaaS/_Reports"

    current_date = datetime.now().strftime("%Y%m%d")
    report_name = f"{index}_nikto_{current_date}.csv"
    report_path = f"/Nikto/Reports/{report_name}"
    
    
    destination_path = os.path.join(reports_dir, report_name)

    docker_command = [
        "docker", "run", "--rm",
        "-v", f"{reports_dir}:/Nikto/Reports",
        "sullo/nikto",
        "-Display", "1234",
        "-h", target,
        "-Format", "csv",
        "-o", report_path,
        "-Tuning", "1234567890abc"
    ]

    print(f"Running Nikto scan for target: {target} with index: {index}")
    command = ' '.join(docker_command)
    print(command)
    subprocess.run(docker_command, check=False)
    print("Nikto scan complete.")

    if os.path.exists(destination_path):
        print(f"Report successfully generated: {destination_path}")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Nikto Scan Automation with Docker")
    parser.add_argument(
        "--target", type=str, required=True,
        help="Target IP Address or website for the VAPT scan (must start with 'http://' or 'https://')"
    )
    parser.add_argument(
        "--index", type=str, required=True,
        help="Index of the Queued Task"
    )
    
    args = parser.parse_args()
    run_nikto_scan(args.target, args.index)
