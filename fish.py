#!/usr/bin/env python3
"""
Test file with intentional security vulnerabilities for NLR testing
This file contains multiple security issues that should be detected by the NLR system
"""

import os
import subprocess
import sqlite3
import hashlib
import pickle
import urllib.request
import urllib.parse

def get_user_by_id(user_id):
    """Vulnerable SQL query with string concatenation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result

def run_command(command):
    """Vulnerable command execution"""
    # VULNERABLE: Using shell=True with user input
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def read_file(filename):
    """Vulnerable file reading without path validation"""
    # VULNERABLE: No path validation
    with open(filename, 'r') as f:
        return f.read()


def hash_password(password):
    """Vulnerable password hashing using MD5"""
    # VULNERABLE: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

def load_user_data(data):
    """Vulnerable deserialization"""
    # VULNERABLE: Using pickle for deserialization
    return pickle.loads(data)

def fetch_url(url):
    """Vulnerable URL fetching"""
    # VULNERABLE: No URL validation
    response = urllib.request.urlopen(url)
    return response.read()

API_KEY = "sk-1234567890abcdef"  # VULNERABLE: Hardcoded API key
DATABASE_PASSWORD = "admin123"    # VULNERABLE: Hardcoded password

def get_system_info():
    """Vulnerable system information disclosure"""
    # VULNERABLE: Exposing sensitive system information
    return {
        "hostname": os.uname().nodename,
        "username": os.getenv("USER"),
        "home_dir": os.path.expanduser("~"),
        "process_id": os.getpid()
    }

def update_counter():
    """Vulnerable counter update"""
    # VULNERABLE: Race condition in file operations
    if os.path.exists("counter.txt"):
        with open("counter.txt", "r") as f:
            count = int(f.read())
    else:
        count = 0
    
    count += 1
    
    with open("counter.txt", "w") as f:
        f.write(str(count))
    
    return count

# Vulnerability 10: Insecure Random
import random

def generate_token():
    """Vulnerable token generation"""
    # VULNERABLE: Using predictable random number generator
    return str(random.randint(1000, 9999))

if __name__ == "__main__":
    # Test the vulnerable functions
    print("Testing vulnerable functions...")
    
    # This should trigger multiple security alerts
    user_id = "1; DROP TABLE users; --"
    get_user_by_id(user_id)
    
    command = "ls -la; rm -rf /"
    run_command(command)
    
    filename = "../../../etc/passwd"
    read_file(filename)
    
    password = "password123"
    hash_password(password)
    
    # These would normally be called with malicious data
    print("Vulnerability test completed")
