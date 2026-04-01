// test-vulns/hardcoded-secrets.js
// VULNERABLE: Hardcoded API keys and secrets
const config = {
  apiKey: 'sk_live_1234567890abcdef',
  databasePassword: 'SuperSecret123!',
  jwtSecret: 'my-secret-key-dont-tell-anyone',
  awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};

// VULNERABLE: Credentials in connection string
const dbUrl = 'postgresql://admin:password123@db.example.com:5432/mydb';

module.exports = config;
