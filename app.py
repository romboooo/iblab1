"""A small Flask API demonstrating secure authentication and data handling."""

from __future__ import annotations

import html
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

import click
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import Flask, current_app, g, jsonify, request


PASSWORD_HASHER = PasswordHasher()
USERNAME_PATTERN = re.compile(r"\A[a-zA-Z0-9_.-]{3,32}\Z")
AUTH_SCHEME = "Bearer"
WRAPPED = TypeVar("WRAPPED", bound=Callable[..., Any])


def _valid_password(password: object) -> bool:
    return isinstance(password, str) and 12 <= len(password) <= 128


def _valid_username(username: object) -> bool:
    return isinstance(username, str) and USERNAME_PATTERN.fullmatch(username) is not None


def get_db() -> sqlite3.Connection:
    """Return the request-scoped SQLite connection."""
    if "db" not in g:
        database_path = current_app.config["DATABASE_PATH"]
        connection = sqlite3.connect(database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def _initialize_database(app: Flask) -> None:
    database_path = Path(app.config["DATABASE_PATH"])
    if str(database_path) != ":memory:":
        database_path.parent.mkdir(parents=True, exist_ok=True)

    with app.app_context():
        get_db().executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            """
        )
        get_db().commit()


def _json_error(message: str, status: int, *, authenticate: bool = False):
    response = jsonify(error=message)
    response.status_code = status
    if authenticate:
        response.headers["WWW-Authenticate"] = 'Bearer realm="api"'
    return response


def require_auth(view: WRAPPED) -> WRAPPED:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token or " " in token:
            return _json_error("Требуется Bearer-токен", 401, authenticate=True)

        try:
            claims = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
                issuer=current_app.config["JWT_ISSUER"],
                audience=current_app.config["JWT_AUDIENCE"],
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
            )
            g.user_id = int(claims["sub"])
        except (jwt.InvalidTokenError, TypeError, ValueError):
            return _json_error("Недействительный или просроченный токен", 401, authenticate=True)
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def _encode_note(row: sqlite3.Row) -> dict[str, Any]:
    """Escape user supplied text before returning it to HTML-capable clients."""
    return {
        "id": row["id"],
        "title": html.escape(row["title"], quote=True),
        "content": html.escape(row["content"], quote=True),
        "created_at": row["created_at"],
    }


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE_PATH=os.environ.get(
            "DATABASE_PATH", str(Path(app.root_path) / "instance" / "api.sqlite3")
        ),
        JWT_SECRET_KEY=None,
        JWT_ISSUER="secure-rest-api",
        JWT_AUDIENCE="secure-rest-api-clients",
        JWT_TTL_SECONDS=900,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
    if test_config:
        app.config.update(test_config)

    secret_key = app.config["JWT_SECRET_KEY"]
    if not isinstance(secret_key, str) or len(secret_key.encode("utf-8")) < 32:
        raise RuntimeError("JWT_SECRET_KEY must contain at least 32 bytes")

    app.extensions["dummy_password_hash"] = PASSWORD_HASHER.hash(
        "not-a-real-account-password-value"
    )
    @app.teardown_appcontext
    def close_db(_error: BaseException | None = None) -> None:
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    _initialize_database(app)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.errorhandler(413)
    def request_too_large(_error):
        return _json_error("Тело запроса превышает допустимый размер", 413)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/auth/login")
    def login():
        if not request.is_json:
            return _json_error("Ожидается JSON", 415)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _json_error("Некорректный JSON", 400)

        username = payload.get("username")
        password = payload.get("password")
        if not _valid_username(username) or not _valid_password(password):
            return _json_error("Неверный логин или пароль", 401)

        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username.lower(),),
        ).fetchone()
        if user is None:
            try:
                PASSWORD_HASHER.verify(
                    current_app.extensions["dummy_password_hash"], password
                )
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                pass
            return _json_error("Неверный логин или пароль", 401)
        try:
            PASSWORD_HASHER.verify(user["password_hash"], password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return _json_error("Неверный логин или пароль", 401)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=app.config["JWT_TTL_SECONDS"])
        token = jwt.encode(
            {
                "sub": str(user["id"]),
                "iat": now,
                "nbf": now,
                "exp": expires_at,
                "iss": app.config["JWT_ISSUER"],
                "aud": app.config["JWT_AUDIENCE"],
            },
            app.config["JWT_SECRET_KEY"],
            algorithm="HS256",
        )
        return jsonify(
            access_token=token,
            token_type=AUTH_SCHEME,
            expires_in=app.config["JWT_TTL_SECONDS"],
        )

    @app.get("/api/data")
    @require_auth
    def list_data():
        rows = get_db().execute(
            "SELECT id, title, content, created_at FROM notes WHERE user_id = ? ORDER BY id",
            (g.user_id,),
        ).fetchall()
        return jsonify(data=[_encode_note(row) for row in rows])

    @app.post("/api/data")
    @require_auth
    def create_data():
        if not request.is_json:
            return _json_error("Ожидается JSON", 415)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"title", "content"}:
            return _json_error("Требуются поля title и content", 400)

        title = payload["title"]
        content = payload["content"]
        if (
            not isinstance(title, str)
            or not 1 <= len(title.strip()) <= 100
            or not isinstance(content, str)
            or not 1 <= len(content.strip()) <= 2000
        ):
            return _json_error("Недопустимая длина title или content", 400)

        db = get_db()
        cursor = db.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (g.user_id, title.strip(), content.strip()),
        )
        db.commit()
        row = db.execute(
            "SELECT id, title, content, created_at FROM notes WHERE id = ? AND user_id = ?",
            (cursor.lastrowid, g.user_id),
        ).fetchone()
        return jsonify(data=_encode_note(row)), 201

    @app.cli.command("create-user")
    @click.argument("username")
    def create_user(username: str) -> None:
        """Create a user; the password is requested without echoing it."""
        normalized_username = username.lower()
        if not _valid_username(normalized_username):
            raise click.BadParameter("логин: 3–32 символа (буквы, цифры, _, . или -)")
        password = click.prompt("Пароль", hide_input=True, confirmation_prompt=True)
        if not _valid_password(password):
            raise click.BadParameter("пароль должен содержать от 12 до 128 символов")
        try:
            get_db().execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (normalized_username, PASSWORD_HASHER.hash(password)),
            )
            get_db().commit()
        except sqlite3.IntegrityError as error:
            raise click.ClickException("Пользователь с таким логином уже существует") from error
        click.echo(f"Пользователь {normalized_username} создан")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
