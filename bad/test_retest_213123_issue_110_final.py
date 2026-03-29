#!/usr/bin/env python3
"""
🚨 FINAL RETEST ISSUE #110 - PR #11
Testing the latest LLM integration fixes in CORRECT repository (ghostnami/vulpy).
This file contains multiple critical vulnerabilities to verify security analysis.
"""

import os
import subprocess
import base64
import hashlib
import sqlite3

# 🚨 Hardcoded credentials
DATABASE_PASSWORD = "final_retest_password_789!"
API_SECRET_KEY = "sk-final-retest-xyz7890123456789"
AWS_ACCESS_KEY_ID = "AKIAFINALRETEST123456789"
AWS_SECRET_ACCESS_KEY = "SECRETFINALRETEST123456789"
JWT_SECRET = "jwt_secret_final_retest_789!"

def vulnerable_function(user_input):
      """
          Function containing multiple security vulnerabilities for testing.
              """
      # 🚨 SQL Injection vulnerability
      query = f"SELECT * FROM users WHERE username='{user_input}' AND password='{DATABASE_PASSWORD}'"
      print(f"Executing query: {query}")

    # 🚨 Command injection
      os.system(f"echo 'Processing user: {user_input}'")

    # 🚨 Information disclosure
      print(f"Database password: {DATABASE_PASSWORD}")
      print(f"API secret key: {API_SECRET_KEY}")
      print(f"AWS credentials: {AWS_ACCESS_KEY_ID}:{AWS_SECRET_ACCESS_KEY}")
      print(f"JWT secret: {JWT_SECRET}")

    # 🚨 Weak cryptography
      weak_hash = hashlib.md5(DATABASE_PASSWORD.encode()).hexdigest()
      print(f"Weak MD5 hash: {weak_hash}")

    # 🚨 Unsafe base64 operations
      encoded = base64.b64encode(b"malicious_payload").decode()
      decoded = base64.b64decode(encoded)
      print(f"Base64 operations: {encoded} -> {decoded}")

    return "Vulnerable function executed successfully"

def database_operations():
      """
          Database operations with vulnerabilities.
              """
      # 🚨 SQL injection in database operations
      conn = sqlite3.connect(':memory:')
      cursor = conn.cursor()

    user_input = "admin'; DROP TABLE users; --"
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)

    conn.close()

if __name__ == "__main__":
      print("🚨 Testing Latest LLM Integration Fixes - FINAL RETEST")
      vulnerable_function("admin")
      database_operations()
      print("✅ Final retest completed")
