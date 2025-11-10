import requests
import sqlite3

# Existing vulnerable code (CONTEXT LINE - Tier 2)
def get_user_posts(username):
    r = requests.get(f'http://127.0.0.1:5000/api/post/{username}')  # SSRF
    return r.json()
