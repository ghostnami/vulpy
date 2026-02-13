#!/usr/bin/env python3
"""
Vulnerable Authentication System - E2E Test File
This file contains multiple security vulnerabilities for testing AppSecInABox analysis
"""

import os
import sqlite3
import hashlib
import pickle
import subprocess
import base64
from flask import Flask, request, render_template_string, session, redirect, url_for

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_12345"  # VULNERABILITY: Hardcoded secret

# VULNERABILITY: SQL Injection - Direct string concatenation
def authenticate_user(username, password):
      conn = sqlite3.connect('users.db')
      cursor = conn.cursor()

    # CRITICAL: SQL Injection vulnerability
      query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
      cursor.execute(query)lgorithm)
      return hashlib.md5(password.encode()).hexdigest()

  # VULNERABILITY: Path Traversal
  def read_file(filename):
        # CRITICAL: Path traversal vulnerability
        with open(f"/tmp/{filename}", 'r') as f:
                  return f.read()

# VULNERABILITY: XSS in template
@app.route('/search')
def search():
      query = request.args.get('q', '')
      # CRITICAL: XSS vulnerability - unsanitized user input in template
      template = f"<h1>Search Results for: {query}</h1>"
      return render_template_string(template)

  # VULNERABILITY: Insecure Session Management
  @app.route('/login', methods=['POST'])
def login():
      username = request.form['username']
      password = request.form['password']

      # VULNERABILITY: No rate limiting, weak session management
      if authenticate_user(username, password):
                session['user'] = username
                session['admin'] = True  # VULNERABILITY: Hardcoded admin privilege
                return redirect(url_for('dashboard'))
            return "Login failed"

# VULNERABILITY: Information Disclosure
@app.route('/debug')
def debug():
      # CRITICAL: Information disclosure - exposing internal data
      return {
          'database_path': '/app/users.db',
          'secret_key': app.secret_key,
          'environment': os.environ,
          'system_info': subprocess.run('uname -a', shell=True, capture_output=True, text=True).stdout
}

# VULNERABILITY: Insecure File Upload
@app.route('/upload', methods=['POST'])
def upload_file():
      file = request.files['file']
    # CRITICAL: No file type validation, direct save
    file.save(f"/uploads/{file.filename}")
    return "File uploaded successfully"

# VULNERABILITY: Weak Random Number Generation
import random
def generate_session_token():
      # VULNERABILITY: Using weak random number generator
      return str(random.randint(1000, 9999))

# VULNERABILITY: Insecure Direct Object Reference
@app.route('/user/<user_id>')
def get_user_profile(user_id):
      # CRITICAL: No authorization check
      conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    c
      result = cursor.fetchone()
      conn.close()
      return result

# VULNERABILITY: Command Injection
def execute_system_command(user_input):
      # CRITICAL: Command injection vulnerability
      result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True, text=True)
      return result.stdout

# VULNERABILITY: Insecure Deserialization
def load_user_data(serialized_data):
      # CRITICAL: Insecure pickle deserialization
      return pickle.loads(base64.b64decode(serialized_data))

# VULNERABILITY: Weak Password Hashing
def hash_password(password):
      # VULNERABILITY: Using MD5 (weak hashing a
