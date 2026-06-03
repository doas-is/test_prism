"""
tests/test_safe_paths.py
Unit tests that also serve as safe reference implementations.
All DB access here uses parameterized queries.
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.utils import is_valid_username, hash_password_safe, weak_sanitize


class TestInputValidation(unittest.TestCase):

    def test_valid_usernames(self):
        self.assertTrue(is_valid_username("alice"))
        self.assertTrue(is_valid_username("bob_99"))
        self.assertTrue(is_valid_username("Admin_User"))

    def test_invalid_usernames(self):
        self.assertFalse(is_valid_username(""))
        self.assertFalse(is_valid_username("al"))              # too short
        self.assertFalse(is_valid_username("alice'; DROP TABLE users--"))
        self.assertFalse(is_valid_username("<script>alert(1)</script>"))

    def test_weak_sanitize_does_not_stop_doublequote(self):
        """Demonstrates that weak_sanitize is insufficient."""
        payload = 'x" OR "1"="1'
        result  = weak_sanitize(payload)
        # Single quotes stripped but double quotes remain — still injectable
        self.assertIn('"', result)

    def test_password_hashing(self):
        pwd    = "MyS3cureP@ss"
        hashed = hash_password_safe(pwd)
        self.assertTrue(hashed.startswith("$2b$"))   # bcrypt prefix
        self.assertNotEqual(hashed, pwd)


class TestSafeQueryPattern(unittest.TestCase):
    """Reference patterns that demonstrate correct parameterized usage."""

    def test_safe_sql_pattern(self):
        """Correct pattern: always use ? placeholders, never string concat."""
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (name TEXT)")
        conn.execute("INSERT INTO t VALUES (?)", ("alice",))
        # ← SAFE: user input goes into params tuple, never into SQL string
        user_input = "'; DROP TABLE t--"
        rows = conn.execute("SELECT * FROM t WHERE name = ?", (user_input,)).fetchall()
        self.assertEqual(rows, [])   # no match — injection neutralized
        conn.close()


if __name__ == "__main__":
    unittest.main()
