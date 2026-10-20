from __future__ import annotations

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path):
    test_app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-key-not-for-production",
            "DATABASE": str(tmp_path / "test.sqlite3"),
        }
    )
    yield test_app


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="alice", password="alice-demo-pass"):
    return client.post("/login", json={"username": username, "password": password})


def test_homepage_renders_html_laboratory_ui(client):
    response = client.get("/")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert "Web AppSec Mini Lab" in body
    assert "SQL Injection" in body
    assert "Broken Access Control / IDOR" in body
    assert "Reflected XSS" in body
    assert "application/json" not in response.content_type
    assert "/static/app.css" in body
    assert "/static/app.js" in body


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}


def test_login_uses_hashed_password_and_starts_session(client):
    response = login(client)
    assert response.status_code == 200
    assert response.json["username"] == "alice"


def test_login_rejects_wrong_password(client):
    response = login(client, password="wrong-password")
    assert response.status_code == 401


def test_login_rejects_non_json_request(client):
    response = client.post("/login", data="username=alice")
    assert response.status_code == 415


def test_sql_injection_exposes_multiple_rows_in_vulnerable_search(client):
    response = client.get("/lab/vulnerable/search", query_string={"q": "' OR 1=1 --"})
    assert response.status_code == 200
    assert len(response.json["results"]) == 2


def test_parameterized_search_does_not_execute_injected_sql(client):
    response = client.get("/search", query_string={"q": "' OR 1=1 --"})
    assert response.status_code == 200
    assert response.json["results"] == []


def test_secure_search_still_finds_a_real_title(client):
    response = client.get("/search", query_string={"q": "Черновик отпуска"})
    assert response.status_code == 200
    assert len(response.json["results"]) == 1
    assert response.json["results"][0]["owner_id"] == 1


def test_note_endpoints_require_login(client):
    assert client.get("/notes/1").status_code == 401
    assert client.get("/lab/vulnerable/notes/1").status_code == 401


def test_vulnerable_note_endpoint_demonstrates_idor(client):
    assert login(client).status_code == 200
    response = client.get("/lab/vulnerable/notes/2")
    assert response.status_code == 200
    assert response.json["note"]["owner_id"] == 2
    assert "Боба" in response.json["note"]["body"]


def test_secure_note_endpoint_blocks_access_to_another_users_note(client):
    assert login(client).status_code == 200
    response = client.get("/notes/2")
    assert response.status_code == 404


def test_user_can_read_own_note(client):
    assert login(client).status_code == 200
    response = client.get("/notes/1")
    assert response.status_code == 200
    assert response.json["note"]["owner_id"] == 1


def test_vulnerable_greeting_reflects_raw_html(client):
    payload = "<script>alert(1)</script>"
    response = client.get("/lab/vulnerable/greet", query_string={"name": payload})
    assert response.status_code == 200
    assert payload in response.get_data(as_text=True)


def test_secure_greeting_escapes_html(client):
    payload = "<script>alert(1)</script>"
    response = client.get("/greet", query_string={"name": payload})
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert payload not in body


def test_secure_responses_have_baseline_security_headers(client):
    response = client.get("/greet")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers


def test_vulnerable_xss_route_intentionally_has_no_csp(client):
    response = client.get("/lab/vulnerable/greet")
    assert "Content-Security-Policy" not in response.headers
