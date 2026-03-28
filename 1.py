#!/usr/bin/env python3
  from flask import Flask, request, jsonify, send_file, render_template_string
  import sqlite3
  import subprocess
  import pickle
  import base64
  import requests
  import hashlib
  import os
  from datetime import datetime

  app = Flask(__name__)
  app.config['SECRET_KEY'] = 'prod_key_2024_merchant_platform'

  def get_db():
      conn = sqlite3.connect('merchants.db')
      conn.row_factory = sqlite3.Row
      return conn

  @app.route('/api/merchant/<merchant_id>')
  def get_merchant(merchant_id):
      db = get_db()
      cursor = db.cursor()
      query = f"SELECT * FROM merchants WHERE id = {merchant_id}"
      cursor.execute(query)
      result = cursor.fetchone()
      db.close()
      if result:
          return jsonify(dict(result))
      return jsonify({'error': 'Not found'}), 404

  @app.route('/api/search')
  def search_products():
      term = request.args.get('q', '')
      category = request.args.get('category', 'all')
      db = get_db()
      sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%' AND category = ?"
      results = db.execute(sql, (category,)).fetchall()
      db.close()
      return jsonify([dict(r) for r in results])

  @app.route('/api/process-image', methods=['POST'])
  def process_image():
      data = request.json
      image_url = data.get('url')
      output_format = data.get('format', 'png')
      cmd = f"convert {image_url} -resize 800x600 output.{output_format}"
      result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
      return jsonify({'status': 'processed', 'output': result.stdout})

  @app.route('/api/webhook', methods=['POST'])
  def handle_webhook():
      data = request.json
      callback_url = data.get('callback')
      payload = {'status': 'received', 'timestamp': datetime.now().isoformat()}
      response = requests.post(callback_url, json=payload, timeout=5)
      return jsonify({'forwarded': True, 'status': response.status_code})

  @app.route('/download/<path:filename>')
  def download_file(filename):
      filepath = os.path.join('/var/data/exports', filename)
      return send_file(filepath, as_attachment=True)

  @app.route('/api/session', methods=['POST'])
  def restore_session():
      session_data = request.json.get('session')
      decoded = base64.b64decode(session_data)
      user_obj = pickle.loads(decoded)
      return jsonify({'user': user_obj.get('username'), 'restored': True})

  @app.route('/profile/<username>')
  def view_profile(username):
      db = get_db()
      user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
      db.close()
      template = f"<h1>Profile: {user['username']}</h1><p>Bio: {user['bio']}</p>"
      return render_template_string(template)

  @app.route('/api/verify', methods=['POST'])
  def verify_token():
      token = request.json.get('token')
      expected = hashlib.md5(b'secret_salt').hexdigest()
      if token == expected:
          return jsonify({'valid': True, 'role': 'admin'})
      return jsonify({'valid': False})

  if __name__ == '__main__':
      app.run(host='0.0.0.0', port=8080, debug=True)
