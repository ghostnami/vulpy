#!/usr/bin/env python3
"""
Simple test file for PR review states
"""

import sqlite3

def get_user(username):
      """Simple function with SQL injection vulnerability"""
      conn = sqlite3.connect('users.db')
      cursor = conn.cursor()

    # VULNERABILITY: SQL Injection
      query = f"SELECT * FROM users WHERE username = '{username}'"
      cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result

if __name__ == '__main__':
      user = get_user('admin')
      print(f"User: {user}")
