import ast
from pathlib import Path

import pytest

from pgups_downloader import PgupsDownloader, safe_filename, sanitize, _atomic_private_write


@pytest.mark.parametrize("value,expected", [
    ("report.pdf", "report.pdf"),
    ("../secret.pdf", "secret.pdf"),
    (r"..\\secret.pdf", "secret.pdf"),
    ("%2e%2e%2fsecret.pdf", "secret.pdf"),
    ("", "unnamed-file"),
    ("..", "unnamed-file"),
])
def test_filename_safe(value, expected):
    assert safe_filename(value) == expected


def test_atomic_private_write(tmp_path):
    target = tmp_path / "secrets.json"
    _atomic_private_write(target, "secret")
    assert target.read_text() == "secret"
    assert target.stat().st_mode & 0o077 == 0


def test_explicit_empty_courses(monkeypatch, tmp_path):
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "nonexistent")
    monkeypatch.setattr(module, "load_config", lambda: {"courses": []})
    dl = PgupsDownloader()
    assert dl.courses == []


def test_http_request_preserves_stream(monkeypatch, tmp_path):
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "nonexistent")
    monkeypatch.setattr(module, "load_config", lambda: {})
    dl = PgupsDownloader()
    captured = {}
    class Dummy:
        status_code = 200
    def fake(method, url, **kwargs):
        captured.update(kwargs)
        return Dummy()
    monkeypatch.setattr(dl.session, "request", fake)
    dl.get("https://sdo.pgups.ru/test", stream=True)
    assert captured["stream"] is True


def test_non_pgups_download_blocked(monkeypatch, tmp_path):
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "nonexistent")
    monkeypatch.setattr(module, "load_config", lambda: {})
    dl = PgupsDownloader()
    assert not dl.download_file("https://evil.example/file", "../secret.txt", tmp_path)


def test_cookies_roundtrip(monkeypatch, tmp_path):
    import pgups_downloader as module
    cookie_file = tmp_path / "cookies.txt"
    monkeypatch.setattr(module, "COOKIES_FILE", cookie_file)
    monkeypatch.setattr(module, "load_config", lambda: {"courses": []})
    dl = PgupsDownloader()
    dl.session.cookies.set("MoodleSession", "value1", domain="sdo.pgups.ru", path="/")
    dl.session.cookies.set("portal", "value2", domain="my.pgups.ru", path="/")
    dl._save_session_cookies()
    content = cookie_file.read_text()
    assert "\\n" not in content
    assert len(content.splitlines()) >= 3
    assert cookie_file.stat().st_mode & 0o077 == 0
    another = PgupsDownloader()
    assert another.session.cookies.get("MoodleSession", domain="sdo.pgups.ru", path="/") == "value1"


def test_threaded_login_cookie_adoption(monkeypatch, tmp_path):
    import threading
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "cookies.txt")
    monkeypatch.setattr(module, "load_config", lambda: {"courses": []})
    dl = PgupsDownloader()
    def login_thread():
        local = dl._http_session()
        local.cookies.set("MoodleSession", "authenticated", domain="sdo.pgups.ru", path="/")
        dl._save_session_cookies()
    t = threading.Thread(target=login_thread)
    t.start()
    t.join()
    assert dl.session.cookies.get("MoodleSession", domain="sdo.pgups.ru", path="/") == "authenticated"


def test_untrusted_redirect(monkeypatch, tmp_path):
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "missing")
    monkeypatch.setattr(module, "load_config", lambda: {"courses": []})
    dl = PgupsDownloader()
    class Redirect:
        status_code = 302
        headers = {"Location": "https://evil.example/stolen"}
        def close(self): pass
    calls = []
    def fake(url, **kwargs):
        calls.append(url)
        return Redirect()
    monkeypatch.setattr(dl, "get", fake)
    with pytest.raises(ValueError, match="Недоверенный"):
        dl._trusted_file_request("GET", "https://sdo.pgups.ru/pluginfile.php/test")
    assert len(calls) == 1


def test_blank_courses_in_web(monkeypatch):
    import web_app
    assert web_app._load_course_names_parallel([]) == []


def test_web_api_rejects_missing_csrf(monkeypatch):
    import web_app
    monkeypatch.setattr(web_app, "_check_web_auth", lambda: True)
    with web_app.app.test_client() as client:
        assert client.get("/").status_code == 200
        assert client.post("/api/settings/courses", json={"url":"4388"}).status_code == 403


@pytest.mark.parametrize("url", [
    "https://evil.example/course/view.php?id=123",
    "http://sdo.pgups.ru/course/view.php?id=123",
    "https://sdo.pgups.ru.evil.example/course/view.php?id=123",
    "https://sdo.pgups.ru@evil.example/course/view.php?id=123",
    "https://sdo.pgups.ru/course/view.php?id=invalid",
])
def test_web_rejects_untrusted_course_url(monkeypatch, url):
    import web_app
    monkeypatch.setattr(web_app, "_check_web_auth", lambda: True)
    with web_app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["csrf"] = "test-token"
        resp = client.post("/api/settings/courses", json={"url":url}, headers={"X-CSRF-Token":"test-token"})
        assert resp.status_code == 400


def test_moodle_link_allowlist():
    from pgups_downloader import trusted_moodle_url
    assert trusted_moodle_url("https://sdo.pgups.ru/mod/assign/view.php?id=5")
    assert not trusted_moodle_url("http://sdo.pgups.ru/mod/assign/view.php?id=5")
    assert not trusted_moodle_url("https://evil.example/mod/assign/view.php?id=5")
    assert not trusted_moodle_url("https://sdo.pgups.ru.evil.example/pluginfile.php")
    assert not trusted_moodle_url("https://sdo.pgups.ru:444/pluginfile.php")


def test_moodle_html_rejects_offsite_assignments(monkeypatch, tmp_path):
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "nonexistent")
    monkeypatch.setattr(module, "load_config", lambda: {"courses":[]})
    dl = module.PgupsDownloader()
    class FakeResponse:
        text = (
            '<a href="https://evil.example/mod/assign/view.php?id=33">Outside</a>'
            '<a href="/mod/assign/view.php?id=34">Inside</a>'
        )
        def raise_for_status(self): pass
    monkeypatch.setattr(dl, "get", lambda *args, **kwargs: FakeResponse())
    assignments = dl.get_assignments_from_course("https://sdo.pgups.ru/course/view.php?id=10")
    assert len(assignments) == 1
    assert assignments[0]["id"] == "34"


def test_captcha_session_survives_new_worker(monkeypatch,tmp_path):
    import threading
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "missing")
    monkeypatch.setattr(module, "load_config", lambda: {"courses":[]})
    dl = module.PgupsDownloader()
    def get_captcha_in_worker():
        dl._http_session().cookies.set("portal_session","secret",domain="my.pgups.ru",path="/")
        dl.publish_session_cookies()
    t = threading.Thread(target=get_captcha_in_worker)
    t.start(); t.join()
    observed = []
    def login_in_new_worker():
        observed.append(dl._http_session().cookies.get("portal_session",domain="my.pgups.ru",path="/"))
    t = threading.Thread(target=login_in_new_worker)
    t.start(); t.join()
    assert observed == ["secret"]


def test_secure_cookies_preserve_attributes(monkeypatch,tmp_path):
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "cookies.txt")
    monkeypatch.setattr(module, "load_config", lambda: {"courses":[]})
    dl = module.PgupsDownloader()
    dl.session.cookies.set("MoodleSession","secret",domain="sdo.pgups.ru",path="/",secure=True)
    dl._save_session_cookies()
    next_dl = module.PgupsDownloader()
    cookie = next(c for c in next_dl.session.cookies if c.name == "MoodleSession")
    assert cookie.secure is True
