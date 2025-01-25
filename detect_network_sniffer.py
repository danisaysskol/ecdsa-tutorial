import os
import psutil
import subprocess
import time

# Suspicious keywords to look for in Python scripts
SUSPICIOUS_PATTERNS = [
    "pollards",
]

# Function to identify processes sniffing the network
def find_sniffing_processes():
    print("[*] Detecting processes using raw sockets or in promiscuous mode...")
    sniffing_processes = []
    current_pid = os.getpid()  # Get the PID of this script

    try:
        # Check for interfaces in promiscuous mode
        result = subprocess.run(["ip", "link"], capture_output=True, text=True)
        if "PROMISC" in result.stdout:
            print("[!] Promiscuous mode detected on an interface.")

        # Check running processes for raw socket usage
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Exclude this script itself
                if proc.info['pid'] == current_pid:
                    continue

                # Look for Python processes
                if proc.info['name'] in ["python", "python3"]:
                    cmdline = " ".join(proc.info['cmdline'])
                    print(f"[*] Checking process: PID={proc.info['pid']}, CMDLINE={cmdline}")

                    # Detect suspicious processes by keywords
                    if any(keyword in cmdline for keyword in SUSPICIOUS_PATTERNS):
                        print(f"[!] Suspicious process detected: PID={proc.info['pid']}, CMDLINE={cmdline}")
                        sniffing_processes.append(proc.info)

                    # Check script files for suspicious patterns
                    for arg in proc.info['cmdline']:
                        if arg.endswith(".py") and os.path.isfile(arg):
                            if scan_file_and_dependencies(arg):
                                print(f"[!] Malicious code detected in script: {arg}")
                                sniffing_processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"[!] Error detecting sniffing processes: {e}")

    return sniffing_processes

# Function to scan a file and its dependencies for suspicious patterns
def scan_file_and_dependencies(file_path, scanned_files=None):
    if scanned_files is None:
        scanned_files = set()

    # Avoid re-scanning files
    if file_path in scanned_files:
        return False

    scanned_files.add(file_path)
    print(f"[*] Scanning file: {file_path}")

    try:
        with open(file_path, 'r') as file:
            code = file.readlines()

        suspicious_found = False

        # Scan for suspicious patterns in the current file
        for line_no, line in enumerate(code, start=1):
            if any(pattern in line for pattern in SUSPICIOUS_PATTERNS):
                print(f"[!] Found suspicious pattern in {file_path} (line {line_no}): {line.strip()}")
                suspicious_found = True

        # Recursively analyze imported modules
        for line in code:
            if line.strip().startswith("import") or line.strip().startswith("from"):
                module_name = extract_module_name(line)
                if module_name:
                    module_path = resolve_module_path(module_name, file_path)
                    if module_path and os.path.isfile(module_path):
                        if scan_file_and_dependencies(module_path, scanned_files):
                            suspicious_found = True

        return suspicious_found
    except Exception as e:
        print(f"[!] Could not scan file {file_path}: {e}")
        return False

# Function to extract module name from an import statement
def extract_module_name(import_line):
    try:
        if import_line.startswith("import"):
            return import_line.split()[1].split('.')[0]
        elif import_line.startswith("from"):
            return import_line.split()[1].split('.')[0]
    except Exception:
        pass
    return None

# Function to resolve the file path of an imported module
def resolve_module_path(module_name, base_file):
    try:
        base_dir = os.path.dirname(base_file)
        module_file = os.path.join(base_dir, f"{module_name}.py")
        if os.path.isfile(module_file):
            return module_file

        # If the module isn't in the same directory, check sys.path or site-packages
        for path in sys.path:
            potential_path = os.path.join(path, f"{module_name}.py")
            if os.path.isfile(potential_path):
                return potential_path
    except Exception:
        pass
    return None

# Function to kill a process by PID
def kill_process(pid):
    try:
        os.kill(pid, 9)  # Send SIGKILL
        print(f"[+] Process PID={pid} successfully terminated.")
    except Exception as e:
        print(f"[!] Failed to kill process PID={pid}: {e}")

# Continuous monitoring loop
def monitor_sniffers():
    print("[*] Starting continuous monitoring of network sniffers...")
    monitored_pids = set()  # Track already processed PIDs to avoid redundant checks

    while True:
        try:
            # Detect sniffing processes
            sniffing_processes = find_sniffing_processes()

            # Analyze and handle each suspicious process
            for proc in sniffing_processes:
                pid = proc.get('pid')
                cmdline = " ".join(proc.get('cmdline', []))

                if pid not in monitored_pids:
                    print(f"[*] Processing suspicious process: PID={pid}, CMDLINE={cmdline}")

                    # If malicious activity is detected, terminate the process
                    if scan_file_and_dependencies(proc['cmdline'][-1]):
                        print(f"[!] Malicious activity detected in process PID={pid}. Terminating...")
                        kill_process(pid)
                    else:
                        print(f"[*] No suspicious activity detected in process PID={pid}.")

                    # Mark this process as handled
                    monitored_pids.add(pid)

            # Sleep for a short period before rechecking
            time.sleep(5)

        except KeyboardInterrupt:
            print("[*] Exiting continuous monitoring...")
            break
        except Exception as e:
            print(f"[!] Error in monitoring loop: {e}")

# Entry point
if __name__ == "__main__":
    monitor_sniffers()
"sniff", "Raw", "promiscuous", 