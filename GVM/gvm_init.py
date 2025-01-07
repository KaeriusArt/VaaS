import os
import subprocess
import time

directory = "/home/ubuntu1/VaaS/GVM/"
try:
    os.chdir(directory)
except FileNotFoundError:
    print(f"Directory {directory} not found. Exiting...")
    exit(1)

sock_path = "/usr/var/run/gvm/gvmd/gvmd.sock"
if os.path.exists(sock_path):
    print("gvmd.sock file found.")
else:
    print("gvmd.sock file not found. Exiting...")
    exit(1)

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command '{command}' failed with error: {e}")
        exit(1)

print("Starting containers...")
run_command("docker compose -f docker-compose.yml -p greenbone-community-edition up -d")
print("Pulling necessary data for containers...")
run_command("docker compose -f docker-compose.yml -p greenbone-community-edition pull notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects")
print("Starting containers with specific services...")
run_command("docker compose -f docker-compose.yml -p greenbone-community-edition up -d notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects")
print("All docker compose commands completed successfully.")

