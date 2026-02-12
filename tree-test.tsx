// Test file for TreeSitter Hybrid Detection - TypeScript/React
// Contains vulnerabilities including React-specific patterns

import React, { useState } from 'react';
import { execSync } from 'child_process';
import crypto from 'crypto';

// 1. React XSS - dangerouslySetInnerHTML
export const UnsafeComponent: React.FC<{ html: string }> = ({ html }) => {
    return (
        <div dangerouslySetInnerHTML={{ __html: html }} /> // HIGH: react-dangerously-set-inner-html
    );
};

// 2. Multiple React XSS instances
export const MessageList: React.FC<{ messages: string[] }> = ({ messages }) => {
    return (
        <div>
            {messages.map((msg, i) => (
                <div key={i} dangerouslySetInnerHTML={{ __html: msg }} /> // HIGH: react-dangerously-set-inner-html
            ))}
        </div>
    );
};

// 3. Code Injection in TypeScript
class UserProcessor {
    processCode(code: string): void {
        eval(code); // CRITICAL: js-dangerous-eval
    }

    executeFunction(fnBody: string): Function {
        return new Function(fnBody); // CRITICAL: js-function-constructor
    }
}

// 4. SQL Injection with TypeScript types
interface User {
    id: number;
    name: string;
}

class UserRepository {
    async findById(userId: number): Promise<User> {
        const query = `SELECT * FROM users WHERE id = ${userId}`; // HIGH: js-sql-template-literal
        return await this.db.query(query);
    }

    async search(searchTerm: string): Promise<User[]> {
        // SQL injection via concatenation
        const sql = "SELECT * FROM users WHERE name = '" + searchTerm + "'"; // HIGH: js-sql-string-concat
        return this.db.execute(sql);
    }

    async update(userId: number, data: any): Promise<void> {
        const updateQuery = `UPDATE users SET data = '${JSON.stringify(data)}' WHERE id = ${userId}`; // HIGH: js-sql-template-literal
        await this.db.query(updateQuery);
    }
}

// 5. XSS in DOM manipulation
function updateDOM(userContent: string): void {
    const element = document.getElementById('content');
    if (element) {
        element.innerHTML = userContent; // HIGH: js-innerhtml-xss
        element.outerHTML = `<div>${userContent}</div>`; // HIGH: js-outerhtml-xss
    }
}

// 6. Weak Cryptography
class SecurityUtils {
    hashPassword(password: string): string {
        return crypto.createHash('md5').update(password).digest('hex'); // MEDIUM: js-weak-crypto-md5
    }

    generateToken(data: string): string {
        return crypto.createHash('sha1').update(data).digest('hex'); // MEDIUM: js-weak-crypto-sha1
    }
}

// 7. Command Injection
class SystemCommands {
    runUserCommand(cmd: string): string {
        return execSync(cmd).toString(); // CRITICAL: js-command-injection-exec
    }

    executeShellCommand(args: string): void {
        execSync('rm -rf ' + args); // CRITICAL: js-command-injection-exec
    }
}

// 8. Path Traversal
import fs from 'fs';

class FileManager {
    readFile(filename: string): string {
        return fs.readFileSync(filename, 'utf-8'); // HIGH: js-path-traversal
    }

    writeFile(path: string, content: string): void {
        fs.writeFileSync(path, content); // HIGH: js-path-traversal
    }

    deleteFile(filepath: string): void {
        fs.unlinkSync(filepath); // HIGH: js-path-traversal
    }
}

// 9. Express API without authentication
import express, { Request, Response } from 'express';

const router = express.Router();

router.get('/admin/users', (req: Request, res: Response) => { // HIGH: js-missing-auth-middleware
    res.json({ users: [] });
});

router.post('/admin/settings', (req: Request, res: Response) => { // HIGH: js-missing-auth-middleware
    res.json({ success: true });
});

router.delete('/api/user/:id', (req: Request, res: Response) => { // HIGH: js-missing-auth-middleware
    res.json({ deleted: true });
});

router.put('/admin/config', (req: Request, res: Response) => { // HIGH: js-missing-auth-middleware
    res.json({ updated: true });
});

// 10. Timing attacks with setTimeout/setInterval
function scheduleEval(code: string): void {
    setTimeout(code, 1000); // HIGH: js-settimeout-string
    setInterval(code, 5000); // HIGH: js-setinterval-string
}

// Safe examples (should NOT trigger)
const SafeComponent: React.FC<{ text: string }> = ({ text }) => {
    return <div>{text}</div>; // Safe: No dangerouslySetInnerHTML
};

class SafeUserRepository {
    async findById(userId: number): Promise<User> {
        // Safe: Parameterized query
        return this.db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    }
}

function safeHash(password: string): string {
    // Safe: SHA-256
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Safe: With authentication
router.get('/api/profile', authenticateUser, (req: Request, res: Response) => {
    res.json(req.user);
});

export { UserProcessor, UserRepository, SecurityUtils, SystemCommands, FileManager };
