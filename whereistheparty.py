#!/usr/bin/env python3
"""
Clean test file for PR review states accuracy testing
Contains exactly 1 vulnerability and 1 safe query
"""

import sqlite3

def get_user_vulnerable(username):
      """Function with SQL injection vulnerability - should be detected"""
      conn = sqlite3.connect('users.db')
      cursor = conn.cursor()

    # VULNERABLE: Direct string interpolation
      query = f"SELECT * FROM users WHERE username = '{username}'"
      cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result

def get_user_safe(username):
      """Function with safe parameterized query - should NOT be detected"""
      conn = sqlite3.connect('users.db')
      cursor = conn.cursor()

    # SAFE: Parameterized query
      cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

    result = cursor.fetchone()
    conn.close()
    return result

if __name__ == '__main__':
      # Test both functions
      user1 = get_user_vulnerable('admin')
      user2 = get_user_safe('admin')
      print(f"Vulnerable result: {user1}")
      print(f"Safe result: {user2}")
