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
