// Test file for TreeSitter Hybrid Detection
// Contains 10+ vulnerabilities that should be detected by javascript.yaml rules

// 1. Code Injection - eval()
function processUserData(userData) {
    eval(userData); // CRITICAL: js-dangerous-eval
}

// 2. Code Injection - Function constructor
const createFunction = (code) => {
    return new Function(code); // CRITICAL: js-function-constructor
};

// 3. Code Injection - setTimeout with string
setTimeout("alert('XSS')", 1000); // HIGH: js-settimeout-string

// 4. Code Injection - setInterval with string
setInterval("console.log('test')", 5000); // HIGH: js-setinterval-string

// 5. XSS - innerHTML
function displayMessage(message) {
    document.getElementById('output').innerHTML = message; // HIGH: js-innerhtml-xss
}

// 6. XSS - outerHTML
function replaceElement(content) {
    document.body.outerHTML = content; // HIGH: js-outerhtml-xss
}

// 7. SQL Injection - String concatenation
function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId; // HIGH: js-sql-string-concat
    return db.execute(query);
}

// 8. SQL Injection - Template literal
async function searchUsers(searchTerm) {
    const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`; // HIGH: js-sql-template-literal
    return await db.query(query);
}

// 9. SQL Injection - Complex query
function deleteUser(userId) {
    const sql = "DELETE FROM users WHERE id = " + userId; // HIGH: js-sql-string-concat
    return db.run(sql);
}

// 10. Weak Crypto - MD5
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex'); // MEDIUM: js-weak-crypto-md5
}

// 11. Weak Crypto - SHA1
function generateToken(data) {
    return crypto.createHash('sha1').update(data).digest('hex'); // MEDIUM: js-weak-crypto-sha1
}

// 12. Path Traversal - readFile
const fs = require('fs');
function readUserFile(filename) {
    return fs.readFileSync('/uploads/' + filename); // HIGH: js-path-traversal
}

// 13. Command Injection - exec
const { exec } = require('child_process');
function runCommand(userInput) {
    exec('ls ' + userInput, (error, stdout) => { // CRITICAL: js-command-injection-exec
        console.log(stdout);
    });
}

// 14. Command Injection - execSync
const { execSync } = require('child_process');
function syncCommand(cmd) {
    return execSync(cmd); // CRITICAL: js-command-injection-exec
}

// 15. Command Injection - spawn
const { spawn } = require('child_process');
function spawnProcess(args) {
    spawn('rm', ['-rf', args]); // HIGH: js-command-injection-spawn
}

// 16. Missing Auth - Express routes (if in Express app)
const express = require('express');
const app = express();

app.get('/admin/users', (req, res) => { // HIGH: js-missing-auth-middleware
    res.json({ users: getAllUsers() });
});

app.post('/admin/delete', (req, res) => { // HIGH: js-missing-auth-middleware
    deleteUser(req.body.userId);
    res.send('Deleted');
});

app.put('/api/settings', (req, res) => { // HIGH: js-missing-auth-middleware
    updateSettings(req.body);
    res.send('Updated');
});

// Safe examples (should NOT be detected)
function safeExamples() {
    // Safe: Using textContent instead of innerHTML
    document.getElementById('safe').textContent = 'Safe text';

    // Safe: Parameterized query (query builder)
    const safeQuery = db.prepare('SELECT * FROM users WHERE id = ?').bind(userId);

    // Safe: SHA-256 hashing
    crypto.createHash('sha256').update(password).digest('hex');

    // Safe: With authentication middleware
    app.get('/api/profile', authenticateUser, (req, res) => {
        res.json(req.user);
    });
}

module.exports = {
    processUserData,
    createFunction,
    displayMessage,
    getUserById,
    searchUsers,
    hashPassword,
    readUserFile,
    runCommand
};
