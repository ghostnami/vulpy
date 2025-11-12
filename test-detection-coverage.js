const db = require('./db');
const { exec } = require('child_process');

// VULNERABILITY 1: SQL Injection (Line 5)
function findUser(username) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  return db.query(query);
}

// VULNERABILITY 2: Command Injection (Line 12)
function runReport(reportName) {
  exec(`python reports/${reportName}.py`, (err, output) => {
    console.log(output);
  });
}

// VULNERABILITY 3: Hardcoded Secret (Line 19)
const STRIPE_SECRET = 'sk_live_9876543210fedcba';

// VULNERABILITY 4: XSS (Line 23)
function outputComment(comment) {
  return `<span>${comment}</span>`;
}

module.exports = { findUser, runReport, outputComment };
