import os
import subprocess
import argparse

def get_home_directory():
    try:
        home_dir = os.path.expanduser("~")
        return home_dir
    except Exception as e:
        return f"Error fetching home directory: {e}"

home_directory = get_home_directory()

def run_nikto_scan(target, index):
    reports_dir = f"{home_directory}/VaaS/_Reports"

    report_name = f"{index}_Nikto.csv"
    report_path = f"/Nikto/Reports/{report_name}"
    
    
    destination_path = os.path.join(reports_dir, report_name)

    docker_command = [
        "docker", "run", "--rm",
        "-v", f"{reports_dir}:/Nikto/Reports",
        "sullo/nikto",
        "-Display", "P",
        "-h", target,
        "-Format", "csv",
        "-o", report_path,
        "-Tuning", "1234567890abc"
    ]

    print(f"Running Nikto scan for target: {target} with index: {index}")
    command = ' '.join(docker_command)
    print(command)
    subprocess.run(docker_command, check=False)
    print("Nikto scan complete. ~100% complete",end="\n")

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
