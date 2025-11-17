// test-vulns/xss-vulnerabilities.jsx
import React from 'react';

// VULNERABLE: Dangerously setting HTML without sanitization
export function UserProfile({ userBio }) {
  return <div dangerouslySetInnerHTML={{ __html: userBio }} />;
}

// VULNERABLE: Direct HTML injection
export function CommentDisplay({ comment }) {
  const div = document.createElement('div');
  div.innerHTML = comment; // XSS vulnerability
  return div;
}

