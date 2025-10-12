#!/usr/bin/env python3
  """
  Advanced API Service - User Management Module
  Implements user authentication, file operations, and session management
  """

  import os
  import jwt
  import yaml
  import hashlib
  import random
  from flask import Flask, request, jsonify, send_file
  from functools import wraps

  app = Flask(__name__)

  # Configuration
  SECRET_KEY = os.getenv("JWT_SECRET", "default-secret-key-12345")
  UPLOAD_DIR = "/var/uploads"


  def require_auth(f):
      """Authentication decorator for protected endpoints"""
      @wraps(f)
      def decorated(*args, **kwargs):
          token = request.headers.get('Authorization', '').replace('Bearer ', '')

          if not token:
              return jsonify({'error': 'Missing token'}), 401

          try:
              # Vulnerability 1: JWT Algorithm Confusion (none algorithm accepted)
              # The LLM needs to spot that algorithms=None allows 'none' algorithm
              payload = jwt.decode(token, SECRET_KEY, algorithms=None)
              request.user = payload
              return f(*args, **kwargs)
          except jwt.InvalidTokenError:
              return jsonify({'error': 'Invalid token'}), 401

      return decorated


  @app.route('/api/user/config', methods=['POST'])
  @require_auth
  def update_user_config():
      """Update user configuration from YAML"""
      config_data = request.data.decode('utf-8')

      # Vulnerability 2: Unsafe YAML deserialization
      # Using yaml.load without Loader is deprecated and allows arbitrary code execution
      # LLM needs to recognize yaml.load() without safe_load or proper Loader
      user_config = yaml.load(config_data)

      # Process the config...
      username = user_config.get('username', 'anonymous')
      return jsonify({'status': 'success', 'username': username})


  @app.route('/api/files/download', methods=['GET'])
  @require_auth
  def download_file():
      """Download user files from upload directory"""
      filename = request.args.get('file')

      # Vulnerability 3: Path traversal through normpath bypass
      # Using normpath doesn't prevent traversal if attacker uses absolute paths
      # or if we don't check the result is still under UPLOAD_DIR
      safe_path = os.path.normpath(os.path.join(UPLOAD_DIR, filename))

      if os.path.exists(safe_path):
          return send_file(safe_path)

      return jsonify({'error': 'File not found'}), 404


  @app.route('/api/user/verify', methods=['POST'])
  def verify_user():
      """Verify user credentials and return session token"""
      data = request.get_json()
      user_id = data.get('user_id')

      # Vulnerability 4: Insecure random for security-sensitive token generation
      # Using random.randint for security tokens is cryptographically weak
      # LLM should flag this as using insecure randomness for auth tokens
      session_token = f"sess_{user_id}_{random.randint(100000, 999999)}"

      return jsonify({
          'status': 'verified',
          'session_token': session_token,
          'expires_in': 3600
      })


  @app.route('/api/admin/reset-password', methods=['POST'])
  @require_auth
  def reset_password():
      """Admin endpoint to reset user passwords"""
      data = request.get_json()
      target_user = data.get('target_user')
      new_password = data.get('new_password')

      # Vulnerability 5: Missing authorization check (IDOR/Missing Function Level Access Control)
      # This endpoint is protected by @require_auth but doesn't verify if the authenticated
      # user is actually an admin. Any authenticated user can reset any password.
      # LLM needs to recognize the missing role/permission check in an admin function

      # Hash the new password
      password_hash = hashlib.md5(new_password.encode()).hexdigest()

      # Update password in database (simulated)
      # db.execute("UPDATE users SET password_hash = ? WHERE username = ?", password_hash, 
  target_user)

      return jsonify({
          'status': 'success',
          'message': f'Password reset for user {target_user}'
      })


  if __name__ == '__main__':
      # Don't run debug in production!
      app.run(debug=False, host='0.0.0.0', port=5000)
