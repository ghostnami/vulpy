import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULNERABILITY 1: SQL Injection
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection
    cursor.execute(query)
    return str(cursor.fetchone())

# VULNERABILITY 2: XSS
@app.route('/search')
def search():
    query = request.args.get('q')
    return render_template_string(f"<h1>Results for: {query}</h1>")  # XSS

# VULNERABILITY 3: Hardcoded Secret
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
DB_PASSWORD = "SuperSecret123!"  # Hardcoded password

# VULNERABILITY 4: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    import os
    result = os.system(f"ping -c 1 {host}")  # Command injection
    return f"Ping result: {result}"

# VULNERABILITY 5: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('name')
    with open(f"/var/www/files/{filename}") as f:  # Path traversal
        return f.read()

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production
