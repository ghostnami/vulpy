const db = require('./db');
const { exec } = require('child_process');

// VULNERABILITY 1: SQL Injection (Line 5)
function getUserById(userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  return db.query(query);
}

// VULNERABILITY 2: Command Injection (Line 12)
function processFile(filename) {
  exec(`cat ${filename}`, (error, stdout) => {
    console.log(stdout);
  });
}

// VULNERABILITY 3: Hardcoded Secret (Line 19)
const API_KEY = 'sk_live_1234567890abcdef';

// VULNERABILITY 4: XSS (Line 23)
function renderComment(comment) {
  return `<div>${comment}</div>`;
}

module.exports = { getUserById, processFile, renderComment };
