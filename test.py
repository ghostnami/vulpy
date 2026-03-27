#!/usr/bin/env python3
"""
Test vulnerable application for security testing
Contains intentional vulnerabilities for testing composed-ai fix generation
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerability 1: SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation - SQL Injection risk
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    user = cursor.fetchone()
    
    conn.close()
    return f"User: {user}"
  
@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


@app.route('/file')
def read_file():
    filename = request.args.get('file', 'README.md')
    
    with open(filename, 'r') as f:
        content = f.read()
    return content

SECRET_KEY = "super_secret_password_123"  # VULNERABLE: Hardcoded secret
app.config['SECRET_KEY'] = SECRET_KEY

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
