// test-vulns/command-injection.js
const { exec } = require('child_process');

// VULNERABLE: Command injection via user input
function convertImage(filename) {
  exec(`convert ${filename} output.png`, (error, stdout) => {
    console.log(stdout);
  });
}

// VULNERABLE: Shell injection in spawn
function pingHost(hostname) {
  require('child_process').execSync(`ping -c 4 ${hostname}`);
}

module.exports = { convertImage, pingHost };
