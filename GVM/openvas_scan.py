import os
import time
import subprocess
import argparse
from datetime import datetime

tools_dir = "/home/ubuntu1/VaaS/GVM/gvm-tools/scripts/"

def check_feed_status(gvm_command):
    try:
        result = subprocess.run(
            gvm_command + [f"{tools_dir}list-feeds.gmp.py"],
            capture_output=True,
            text=True,
        )
        # Check if any line doesn't have "Up-to-date..."
        for line in result.stdout.splitlines()[4:]:
            print(line)

            if "Up-to-date..." not in line:
                if "Update in progress..." in line:
                    wait_for_update(gvm_command)
                else:
                    return False
        return True
    except Exception as e:
        print(f"Error checking feed status: {e}")
        return False


def update_feeds():
    print("Updating feeds...")
    try:
        subprocess.run(
            [
                "docker", "compose", "-f", "docker-compose.yml", "-p", "greenbone-community-edition",
                "pull", "notus-data", "vulnerability-tests", "scap-data", "dfn-cert-data",
                "cert-bund-data", "report-formats", "data-objects"
            ],
            check=True  # Ensures an exception is raised if the command fails
        )
        subprocess.run(
            [
                "docker", "compose", "-f", "docker-compose.yml", "-p", "greenbone-community-edition",
                "up", "-d", "notus-data", "vulnerability-tests", "scap-data", "dfn-cert-data",
                "cert-bund-data", "report-formats", "data-objects"
            ],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error updating feeds: Command failed with return code {e.returncode}")
    except Exception as e:
        print(f"Error updating feeds: {e}")



# Wait for feeds to reflect the update
def wait_for_update(gvm_command):
    print("Waiting for updates to reflect...")
    while not check_feed_status(gvm_command):
        print("Feeds are still not updated. Checking again in 30 seconds...")
        time.sleep(30)
    print("Feeds are now up-to-date.")


# Perform VAPT scan
def perform_scan(gvm_command, target, index):
    print(f"Target: {target}")

    cleaned_target = target.replace("https://", "").replace("http://", "")
    current_date = datetime.now().strftime("%Y%m%d")
    report_name = f"{index}_openvas_{current_date}"

    try:
        # Start scan
        subprocess.run(
            gvm_command
            + [f"{tools_dir}scan-new-system.gmp.py", cleaned_target, "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"]
        )

        # Check the status of the scan
        while True:
            result = subprocess.run(
                gvm_command + [f"{tools_dir}list-reports.gmp.py", "All"],
                capture_output=True,
                text=True,
            )
            lines = result.stdout.splitlines()
            status, progress = lines[6].split()[13], lines[6].split()[15]
            uid = lines[6].split()[2]
            print(f"\rUID: {uid} Current Status: {status}, Progress: {progress}            ", end="")
            if status == "Done" and progress == "100%":
                
                # Export report
                subprocess.run(
                    gvm_command + [f"{tools_dir}export-csv-report.gmp.py", uid, f"/home/ubuntu1/VaaS/_Reports/{report_name}"]
                )
                subprocess.run(gvm_command + [f"{tools_dir}clean-sensor.gmp.py"])
                break

            time.sleep(10)
    except Exception as e:
        print(f"Error performing scan: {e}")


def main():
    parser = argparse.ArgumentParser(description="Greenbone Vulnerability Manager Automation")
    parser.add_argument("--target", type=str, required=True, help="Target IP Address or website for the VAPT scan (must start with 'http://' or 'https://')")
    parser.add_argument("--index", type=str, required=True, help="Index of the Queued Task")
    args = parser.parse_args()
    gvm_command = ["gvm-script","--gmp-username","admin","--gmp-password","admin1234","socket","--socketpath","/usr/var/run/gvm/gvmd/gvmd.sock",]

    print(f"The queued index '{args.index}' is now under OpenVas.")

    if check_feed_status(gvm_command):
        print("All feeds are up-to-date. Proceeding to VAPT scan...")
        perform_scan(gvm_command, args.target, args.index)
    else:
        update_feeds()
        wait_for_update(gvm_command)
        perform_scan(gvm_command, args.target, args.index)

if __name__ == "__main__":
    main()
