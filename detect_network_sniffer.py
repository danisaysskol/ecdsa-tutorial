import os
import sys
import psutil
import subprocess
import time
import dotenv
from openai import OpenAI

dotenv.load_dotenv()

client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Function to analyze code using ChatGPT
def analyze_code_with_chatgpt(code):
    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a security expert analyzing code for potential ECDSA attacks."},
                {
                    "role": "user", 
                    "content": f"Analyze the following code and determine ONLY if it contains an attack on ECDSA (like Pollard's rho). Respond with ONLY YES or NO:\n\n{code}"
                }
            ]
        )
        response = completion.choices[0].message.content.strip().upper()
        return response == "YES"
    except Exception as e:
        print(f"[!] Error analyzing code with ChatGPT: {e}")
        return False

# Function to identify processes sniffing the network
def find_sniffing_processes(scanned_files):
    print("[*] Detecting processes using raw sockets or in promiscuous mode...")
    sniffing_processes = []
    current_pid = os.getpid()  

    try:
        # Check for interfaces in promiscuous mode
        result = subprocess.run(["ip", "link"], capture_output=True, text=True)
        if "PROMISC" in result.stdout:
            print("[!] Promiscuous mode detected on an interface.")

        # Check running processes for raw socket usage
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['pid'] == current_pid:  # Skip this script
                    continue

                # Look for Python processes
                if proc.info['name'] in ["python", "python3"]:
                    cmdline = " ".join(proc.info['cmdline'])
                    print(f"[*] Checking process: PID={proc.info['pid']}, CMDLINE={cmdline}")

                    # Check script files
                    for arg in proc.info['cmdline']:
                        if arg.endswith(".py") and os.path.isfile(arg):
                            suspicious_files = check_suspicious_files(arg, scanned_files)
                            if suspicious_files:
                                proc.info['suspicious_files'] = suspicious_files
                                sniffing_processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"[!] Error detecting sniffing processes: {e}")

    return sniffing_processes

# Function to check for suspicious files
def check_suspicious_files(file_path, scanned_files):
    if file_path in scanned_files:
        return []  # Skip already scanned files

    scanned_files.add(file_path)  # Mark file as scanned
    print(f"[*] Scanning file: {file_path}")
    suspicious_files = []

    try:
        with open(file_path, 'r') as file:
            code = file.read()

        if analyze_code_with_chatgpt(code):
            print(f"[!] ChatGPT detected potential ECDSA attack in {file_path}")
            suspicious_files.append(file_path)

        # Recursively analyze imported modules
        for line in code.splitlines():
            if line.strip().startswith("import") or line.strip().startswith("from"):
                module_name = extract_module_name(line)
                if module_name:
                    module_path = resolve_module_path(module_name, file_path)
                    if module_path and os.path.isfile(module_path):
                        suspicious_files.extend(check_suspicious_files(module_path, scanned_files))
    except Exception as e:
        print(f"[!] Could not scan file {file_path}: {e}")
    
    return suspicious_files

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

        # If not found in the same directory, check sys.path
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
    monitored_pids = set()  # Track already processed PIDs
    scanned_files = set()   # Track already scanned files

    while True:
        try:
            sniffing_processes = find_sniffing_processes(scanned_files)

            for proc in sniffing_processes:
                pid = proc.get('pid')
                cmdline = " ".join(proc.get('cmdline', []))

                if pid not in monitored_pids:
                    print(f"[*] Processing suspicious process: PID={pid}, CMDLINE={cmdline}")

                    # Kill process if suspicious files are detected
                    if proc.get('suspicious_files'):
                        print(f"[!] Malicious activity detected in process PID={pid}. Terminating...")
                        kill_process(pid)
                    else:
                        print(f"[*] No suspicious activity detected in process PID={pid}.")

                    monitored_pids.add(pid)  # Mark process as handled

            time.sleep(15)
        except KeyboardInterrupt:
            print("[*] Exiting continuous monitoring...")
            break
        except Exception as e:
            print(f"[!] Error in monitoring loop: {e}")

# Entry point
if __name__ == "__main__":
    monitor_sniffers()
