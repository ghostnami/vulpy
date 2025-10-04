#!/usr/bin/env python3
"""
🚨 LATEST REDEPLOYMENT TEST - PR #8
Testing the latest redployment for improved comment quality.
"""

import os
import subprocess
import base64

# 🚨 Hardcoded credentials
SECRET_KEY = "redployment_test_123!"
API_TOKEN = "sk-redployment-test-abcdef1234567890"
AWS_ACCESS_KEY = "AKIAREDEPLOYMENTTEST123456"

def vulnerable_function(user_input):
      # 🚨 SQL Injection vulnerability
      query = f"SELECT * FROM users WHERE name='{user_input}' AND secret='{SECRET_KEY}'"
      print(f"Executing query: {query}")

    # 🚨 Command injection
      os.system(f"echo 'Processing user: {user_input}'")

    # 🚨 Information disclosure
      print(f"Secret key: {SECRET_KEY}")
      print(f"API token: {API_TOKEN}")
      print(f"AWS access key: {AWS_ACCESS_KEY}")

    # 🚨 Unsafe base64 operations
      encoded = base64.b64encode(b"malicious_payload").decode()
      decoded = base64.b64decode(encoded)
      print(f"Base64 operations: {encoded} -> {decoded}")

    return "Vulnerable function executed"

if __name__ == "__main__":
      vulnerable_function("admin")
