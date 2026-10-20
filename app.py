"""Локальная учебная лаборатория AppSec: уязвимые и исправленные endpoints.

ВНИМАНИЕ: маршруты /lab/vulnerable/* намеренно уязвимы.
Запускайте только локально и не публикуйте это приложение в интернет.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, g, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash


DEMO_USERS = (
    ("alice", "alice-demo-pass"),
    ("bob", "bob-demo-pass"),
)


def _connect(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_database(database_path: str) -> None:
    """Создаёт схему и заполняет БД безопасными демонстрационными данными."""
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = _connect(database_path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            user_ids: dict[str, int] = {}
            for username, password in DEMO_USERS:
                cursor = connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                user_ids[username] = int(cursor.lastrowid)

            connection.executemany(
                "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                [
                    (user_ids["alice"], "Черновик отпуска", "Демо-заметка Алисы: план поездки."),
                    (user_ids["bob"], "Заметки о проекте", "Демо-заметка Боба: внутренние проектные идеи."),
                ],
            )
        connection.commit()
    finally:
        connection.close()


def _note_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "title": row["title"],
        "body": row["body"],
    }


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    default_db = os.path.join(app.instance_path, "web_appsec_lab.sqlite3")
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("WEB_APPSEC_DATABASE") or default_db,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    init_database(app.config["DATABASE"])

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = _connect(app.config["DATABASE"])
        return g.db

    @app.teardown_appcontext
    def close_db(_error: BaseException | None = None) -> None:
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def require_login(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not session.get("user_id"):
                return jsonify(error="Требуется вход"), 401
            return view(*args, **kwargs)
        return wrapped

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Уязвимые маршруты намеренно оставлены без CSP, чтобы наглядно показать,
        # что контекстное экранирование — первичная защита от XSS, а CSP — дополнительная.
        if not request.path.startswith("/lab/vulnerable/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            )
        return response

    @app.get("/")
    def index():
        # Главная страница лаборатории. JSON-статус доступен отдельно по /health.
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/login")
    def login():
        if not request.is_json:
            return jsonify(error="Ожидается JSON"), 415
        payload = request.get_json(silent=True) or {}
        username = payload.get("username", "")
        password = payload.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(error="Неверные учётные данные"), 401

        row = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None or not check_password_hash(row["password_hash"], password):
            return jsonify(error="Неверные учётные данные"), 401

        session.clear()
        session["user_id"] = int(row["id"])
        return jsonify(message="Вход выполнен", username=row["username"])

    # ---------------------------------------------------------------------
    # SQL injection: намеренно уязвимый и исправленный варианты поиска.
    # ---------------------------------------------------------------------
    @app.get("/lab/vulnerable/search")
    def vulnerable_search():
        query = request.args.get("q", "")
        # INTENTIONALLY VULNERABLE: пользовательские данные конкатенируются в SQL.
        sql = f"SELECT id, owner_id, title, body FROM notes WHERE title = '{query}'"
        try:
            rows = get_db().execute(sql).fetchall()
        except sqlite3.Error:
            return jsonify(error="Ошибка SQL-запроса (демо уязвимого варианта)"), 400
        return jsonify(results=[_note_to_dict(row) for row in rows])

    @app.get("/search")
    def secure_search():
        query = request.args.get("q", "")
        rows = get_db().execute(
            "SELECT id, owner_id, title, body FROM notes WHERE title = ?",
            (query,),
        ).fetchall()
        return jsonify(results=[_note_to_dict(row) for row in rows])

    # ---------------------------------------------------------------------
    # Broken access control / IDOR: оба маршрута требуют входа; уязвимый
    # вариант не проверяет владельца заметки, исправленный делает это в SQL.
    # ---------------------------------------------------------------------
    @app.get("/lab/vulnerable/notes/<int:note_id>")
    @require_login
    def vulnerable_get_note(note_id: int):
        row = get_db().execute(
            "SELECT id, owner_id, title, body FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
        if row is None:
            return jsonify(error="Заметка не найдена"), 404
        # INTENTIONALLY VULNERABLE: авторизованный пользователь видит чужую заметку.
        return jsonify(note=_note_to_dict(row))

    @app.get("/notes/<int:note_id>")
    @require_login
    def secure_get_note(note_id: int):
        row = get_db().execute(
            "SELECT id, owner_id, title, body FROM notes WHERE id = ? AND owner_id = ?",
            (note_id, session["user_id"]),
        ).fetchone()
        # Возвращаем 404 и для несуществующих, и для чужих объектов.
        if row is None:
            return jsonify(error="Заметка не найдена"), 404
        return jsonify(note=_note_to_dict(row))

    # ---------------------------------------------------------------------
    # XSS: уязвимый маршрут вставляет ввод прямо в HTML; безопасный передаёт
    # значение в Jinja-шаблон, где включено контекстное автоэкранирование.
    # ---------------------------------------------------------------------
    @app.get("/lab/vulnerable/greet")
    def vulnerable_greet():
        name = request.args.get("name", "гость")
        # INTENTIONALLY VULNERABLE: отражаем пользовательский ввод без экранирования.
        return f"<!doctype html><html lang=ru><meta charset=utf-8><p>Привет, {name}!</p></html>"

    @app.get("/greet")
    def secure_greet():
        name = request.args.get("name", "гость")
        return render_template("greet.html", name=name)

    return app


app = create_app()

if __name__ == "__main__":
    # Намеренно привязываемся только к loopback-интерфейсу.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
