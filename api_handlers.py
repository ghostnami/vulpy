#!/usr/bin/env python3
"""
API Request Handlers
Handles HTTP requests for user management endpoints
"""

import os
import hashlib
from flask import Flask, request, jsonify, make_response
from database_utils import DatabaseManager

app = Flask(__name__)
db = DatabaseManager()


@app.route('/api/users/search', methods=['GET'])
def search_users():
    """Search for users by username or email"""
    search_term = request.args.get('q', '')
    sort_by = request.args.get('sort', 'username')

    # Vulnerability 1: Using vulnerable database function
    # This propagates the SQL injection from database_utils.py
    results = db.search_users(search_term, sort_by)

    return jsonify({'users': results, 'count': len(results)})


@app.route('/api/users/<username>', methods=['GET'])
def get_user(username):
    """Get user details by username"""
    # Vulnerability 2: Path traversal in username parameter
    # Username could contain '../' or absolute paths
    # Also uses vulnerable SQL injection function from database_utils
    user = db.get_user_by_username(username)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(user)


@app.route('/api/users/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Vulnerability 3: Weak password hashing (MD5)
    # MD5 is cryptographically broken and unsuitable for passwords
    password_hash = hashlib.md5(password.encode()).hexdigest()

    # Check credentials (vulnerable SQL injection)
    user = db.get_user_by_username(username)

    if user:
        # Create session with insecure serialization
        session_data = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'is_admin': user['role'] == 'admin'
        }

        # Vulnerability 4: Using vulnerable pickle serialization
        db.save_session_data(user['id'], session_data)

        response = make_response(jsonify({'success': True, 'user': user}))

        # Vulnerability 5: Missing Secure flag on cookie
        # Cookie can be transmitted over unencrypted HTTP
        response.set_cookie('session_id', str(user['id']), httponly=True)

        return response

    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/users/export', methods=['GET'])
def export_users():
    """Export user data to file"""
    output_format = request.args.get('format', 'csv')
    filename = request.args.get('filename', 'users')

    # Vulnerability 6: Path traversal in file operations
    # filename parameter not validated, could write to arbitrary locations
    export_path = os.path.join('/var/exports', f"{filename}.{output_format}")

    # Fetch all users (vulnerable SQL)
    users = db.search_users('', 'username')

    # Write to file (simplified)
    with open(export_path, 'w') as f:
        f.write("id,username,email,role\n")
        for user in users:
            f.write(f"{user['id']},{user['username']},{user['email']},{user['role']}\n")

    return jsonify({'success': True, 'file': export_path})


@app.route('/api/admin/execute', methods=['POST'])
def admin_execute():
    """Admin endpoint to execute database queries"""
    data = request.get_json()
    query = data.get('query')

    # Vulnerability 7: Missing authorization check
    # No verification that user is actually an admin
    # Anyone can execute arbitrary SQL queries

    # Vulnerability 8: Direct SQL execution from user input
    results = db.execute_query(query)

    return jsonify({'results': results})


if __name__ == '__main__':
    # Vulnerability 9: Debug mode enabled in production
    # Exposes sensitive information and allows code execution
    debug_mode = os.getenv('DEBUG', 'True').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=8080)
