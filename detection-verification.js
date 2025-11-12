const db = require('./db');
const { exec } = require('child_process');

// VULNERABILITY 1: SQL Injection (Line 5)
function getUserByUsername(username) {
  return db.query("SELECT * FROM users WHERE username = '" + username + "'");
}

// VULNERABILITY 2: Command Injection (Line 11)
function runUserCommand(input) {
  exec(`sh -c "${input}"`, (error, stdout) => {
    if (error) {
      console.error('Command failed', error);
    }
    console.log(stdout);
  });
}

// VULNERABILITY 3: Hardcoded Secret (Line 19)
const AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';

// VULNERABILITY 4: XSS (Line 23)
function renderComment(comment) {
  return `<section>${comment}</section>`;
}

module.exports = { getUserByUsername, runUserCommand, renderComment };
