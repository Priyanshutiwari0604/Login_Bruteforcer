# Web Login Brute Force Tool

A Python tool for testing login credentials against web applications.

## Legal Notice

**AUTHORIZED USE ONLY** - This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal.

## Installation

```bash
git clone https://github.com/username/web-login-bruteforce.git
cd web-login-bruteforce
pip install requests
```

## Usage

```bash
python bruteforce.py
```

Follow the prompts:
- **Target URL**: Login page URL
- **Username**: Username to test
- **Password File**: Path to password list
- **Failure String**: Text that appears on failed login
- **Delay**: Seconds between attempts (recommended: 1-2)

## Example

```
[+] Enter Page URL: http://example.com/login
[+] Enter Username: admin
[+] Enter Password File: passwords.txt
[+] Enter String that occurs when login fails: Login failed
[+] Enter delay between attempts: 1
```

## Requirements

- Python 3.6+
- requests library

## Password File Format

One password per line:
```
admin
password
123456
```

## Features

- Interactive setup
- Configurable delays
- Color-coded output
- Error handling
- Success detection

## How It Works

1. Reads passwords from file
2. Sends POST requests to target URL
3. Checks response for failure string
4. Reports successful credentials

**File not found**: Verify password file path
**No success**: Check failure string accuracy
