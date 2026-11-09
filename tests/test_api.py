"""Integration tests for the authentication and data API."""

import tempfile
import unittest
from pathlib import Path
from secrets import token_hex

from argon2 import PasswordHasher

from app import create_app, get_db

TEST_CREDENTIAL = "correct horse battery"
WRONG_CREDENTIAL = "wrong password"


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(database_path),
                "JWT_SECRET_KEY": token_hex(32),
                "JWT_TTL_SECONDS": 60,
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            get_db().execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("student", PasswordHasher().hash(TEST_CREDENTIAL)),
            )
            get_db().commit()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_health_is_public(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})

    def test_login_returns_jwt_and_invalid_credentials_are_rejected(self):
        response = self.client.post(
            "/auth/login",
            json={"username": "student", "password": TEST_CREDENTIAL},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["token_type"], "Bearer")
        self.assertEqual(response.json["expires_in"], 60)
        self.assertTrue(response.json["access_token"])

        invalid = self.client.post(
            "/auth/login",
            json={"username": "student", "password": WRONG_CREDENTIAL},
        )
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(invalid.json, {"error": "Неверный логин или пароль"})

    def test_private_data_requires_valid_token(self):
        anonymous = self.client.get("/api/data")
        self.assertEqual(anonymous.status_code, 401)
        self.assertIn("WWW-Authenticate", anonymous.headers)

        invalid = self.client.get("/api/data", headers={"Authorization": "Bearer invalid"})
        self.assertEqual(invalid.status_code, 401)

    def test_notes_are_owned_by_user_and_html_escaped_in_responses(self):
        login = self.client.post(
            "/auth/login",
            json={"username": "student", "password": TEST_CREDENTIAL},
        )
        token = login.json["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        created = self.client.post(
            "/api/data",
            json={"title": "<script>alert(1)</script>", "content": "<img src=x onerror=alert(1)>"},
            headers=headers,
        )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json["data"]["title"], "&lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertEqual(
            created.json["data"]["content"],
            "&lt;img src=x onerror=alert(1)&gt;",
        )
        listed = self.client.get("/api/data", headers=headers)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json["data"][0]["id"], created.json["data"]["id"])

    def test_sqli_like_content_is_stored_as_data(self):
        login = self.client.post(
            "/auth/login",
            json={"username": "student", "password": TEST_CREDENTIAL},
        )
        headers = {"Authorization": f"Bearer {login.json['access_token']}"}
        injected_text = "'); DROP TABLE users; --"

        created = self.client.post(
            "/api/data",
            json={"title": "SQLi probe", "content": injected_text},
            headers=headers,
        )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json["data"]["content"], "&#x27;); DROP TABLE users; --")
        with self.app.app_context():
            stored = get_db().execute(
                "SELECT content FROM notes WHERE id = ?",
                (created.json["data"]["id"],),
            ).fetchone()
            self.assertEqual(stored["content"], injected_text)
            self.assertEqual(
                get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 1
            )


if __name__ == "__main__":
    unittest.main()
