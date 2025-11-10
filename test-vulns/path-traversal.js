// test-vulns/path-traversal.js
const fs = require('fs');
const path = require('path');

// VULNERABLE: Path traversal - no sanitization
function readUserFile(filename) {
  const filePath = path.join('./uploads/', filename);
  return fs.readFileSync(filePath, 'utf8');
}

// VULNERABLE: Direct file access without validation
function serveFile(req, res) {
  const requestedFile = req.query.file;
  res.sendFile('/var/www/uploads/' + requestedFile);
}

module.exports = { readUserFile, serveFile };
