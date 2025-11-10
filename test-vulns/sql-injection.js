// test-vulns/sql-injection.js
const db = require('./db');

// VULNERABLE: SQL injection via string concatenation
async function getUserById(userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  return await db.query(query);
}

// VULNERABLE: SQL injection in ORM raw query
async function searchUsers(searchTerm) {
  return await db.raw(`SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`);
}

module.exports = { getUserById, searchUsers };
