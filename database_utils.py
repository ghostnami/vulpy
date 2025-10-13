#!/usr/bin/env python3
"""
Database Utilities Module
Provides database access functions for the application
"""

import sqlite3
import pickle
import base64
from typing import Dict, List, Any, Optional


class DatabaseManager:
    """Manages database connections and queries"""

    def __init__(self, db_path: str = "app.db"):
        self.db_path = db_path
        self.connection = None

    def connect(self):
        """Establish database connection"""
        self.connection = sqlite3.connect(self.db_path)
        return self.connection

    def execute_query(self, query: str, params: Optional[tuple] = None):
        """Execute a database query"""
        if not self.connection:
            self.connect()

        cursor = self.connection.cursor()

        # Vulnerability 1: SQL Injection via string formatting
        # The query parameter might contain user input that gets formatted
        if params:
            # This looks safe but params could contain formatted strings
            cursor.execute(query, params)
        else:
            # Direct execution without parameterization
            cursor.execute(query)

        return cursor.fetchall()

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve user by username"""
        # Vulnerability 2: SQL Injection through string concatenation
        # Building query with string concatenation instead of parameters
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"

        result = self.execute_query(query)

        if result:
            return {
                'id': result[0][0],
                'username': result[0][1],
                'email': result[0][2],
                'role': result[0][3]
            }
        return None

    def search_users(self, search_term: str, order_by: str = "username") -> List[Dict[str, Any]]:
        """Search users with a search term"""
        # Vulnerability 3: SQL Injection through ORDER BY clause
        # order_by parameter is directly inserted into query
        query = f"""
            SELECT id, username, email, role
            FROM users
            WHERE username LIKE '%{search_term}%'
            OR email LIKE '%{search_term}%'
            ORDER BY {order_by}
        """

        results = self.execute_query(query)

        return [
            {'id': row[0], 'username': row[1], 'email': row[2], 'role': row[3]}
            for row in results
        ]

    def save_session_data(self, user_id: int, session_data: Dict[str, Any]):
        """Save user session data"""
        # Vulnerability 4: Insecure deserialization using pickle
        # Pickle is unsafe for untrusted data - allows arbitrary code execution
        serialized_data = base64.b64encode(pickle.dumps(session_data)).decode('utf-8')

        query = "INSERT INTO sessions (user_id, data) VALUES (?, ?)"
        self.execute_query(query, (user_id, serialized_data))
        self.connection.commit()

    def load_session_data(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Load user session data"""
        query = "SELECT data FROM sessions WHERE user_id = ?"
        result = self.execute_query(query, (user_id,))

        if result and result[0]:
            serialized_data = result[0][0]
            # Vulnerability 5: Unsafe deserialization
            # Unpickling untrusted data can execute arbitrary code
            session_data = pickle.loads(base64.b64decode(serialized_data))
            return session_data

        return None

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
