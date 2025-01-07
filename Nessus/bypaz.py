import time
import subprocess

password = "ubuntu1"

# Function to run a command with sudo and password
def run_sudo_command(command):
    result = subprocess.run(
        ["sudo", "-S"] + command,
        input=password + "\n",
        text=True,
        capture_output=True
    )
    if result.returncode != 0:
        print(f"Error executing command: {' '.join(command)}")
        print(result.stderr)
    else:
        print(f"Command executed successfully: {' '.join(command)}")

# Disable NTP
run_sudo_command(["timedatectl", "set-ntp", "false"])
time.sleep(10)

# Set the time 95 days in the future
future_date = subprocess.run(
    ["date", "-d", "+95 days", "+%Y-%m-%d %H:%M:%S"], 
    capture_output=True, 
    text=True
).stdout.strip()
run_sudo_command(["timedatectl", "set-time", future_date])
time.sleep(10)

# Restart the Nessus container
subprocess.run(["docker", "stop", "Nessus"])
subprocess.run(["docker", "start", "Nessus"])
time.sleep(30)

# Set the time back 95 days
past_date = subprocess.run(
    ["date", "-d", "-95 days", "+%Y-%m-%d %H:%M:%S"], 
    capture_output=True, 
    text=True
).stdout.strip()
run_sudo_command(["timedatectl", "set-time", past_date])
time.sleep(30)

# Re-enable NTP
run_sudo_command(["timedatectl", "set-ntp", "true"])

# Restart the Nessus container again
subprocess.run(["docker", "stop", "Nessus"])
time.sleep(30)
subprocess.run(["docker", "start", "Nessus"])
time.sleep(60)
