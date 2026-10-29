"""Offline regression tests: no university credentials or network required."""
from datetime import datetime
from pathlib import Path

import pytest

from storage import Store
from calendar_utils import create_ics, parse_deadline


def test_grade_history_persists_across_restarts(tmp_path):
    db = tmp_path / "progress.sqlite3"
    first = Store(db)
    first.snapshot_course("42", "Тестовый курс", [
        {"id":"777", "name":"Лабораторная", "status":". не сдано", "deadline":"13.11.2026 23:59"}])
    assert first.history() == []
    next_items = [{"id":"777", "name":"Лабораторная", "status":"+ зачтено", "deadline":"13.11.2026 23:59"}]
    events = Store(db).snapshot_course("42", "Тестовый курс", next_items)
    assert len(events) == 1
    assert events[0]["old_status"] == ". не сдано"
    assert next_items[0]["changed"] is True
    assert Store(db).history()[0]["new_status"] == "+ зачтено"
    assert Store(db).deadlines()[0]["item_id"] == "777"
    assert Store(db).snapshot_course("42", "Тестовый курс", next_items) == []


def test_grade_history_disambiguates_duplicate_names(tmp_path):
    db = Store(tmp_path / "history.db")
    db.snapshot_course("1", "Course", [
        {"id":"10", "name":"Работа", "status":". не сдано"},
        {"id":"11", "name":"Работа", "status":". не сдано"},
    ])
    db.snapshot_course("1", "Course", [
        {"id":"10", "name":"Работа", "status":"+ отлично"},
        {"id":"11", "name":"Работа", "status":". не сдано"},
    ])
    assert len(db.history()) == 1
    assert db.history()[0]["item_id"] == "10"


@pytest.mark.parametrize("value,year,month,day", [
    ("13.11.2026 23:59",2026,11,13),
    ("пятница, 13 ноября 2026, 23:59",2026,11,13),
    ("1 мая 2027 12:30",2027,5,1),
    ("5/12/2026",2026,12,5),
])
def test_deadline_parse(value, year, month, day):
    dt = parse_deadline(value)
    assert dt is not None
    assert (dt.year,dt.month,dt.day) == (year,month,day)


def test_invalid_deadline_skipped():
    assert parse_deadline("неизвестно") is None
    assert parse_deadline("35.13.2027") is None


def test_ics_export():
    cal = create_ics([{
        "course_id":"10", "item_id":"20", "course_name":"Курс",
        "name":"Лабораторная", "status":". не сдано", "deadline":"13.11.2026 23:59"}])
    assert cal.startswith("BEGIN:VCALENDAR\r\n")
    assert "BEGIN:VEVENT" in cal
    assert "UID:10-20@pgups-downloader" in cal
    assert "DTSTART:20261113T205900Z" in cal
    assert cal.endswith("END:VCALENDAR\r\n")


def test_web_local_pages_and_api(monkeypatch, tmp_path):
    import web_app
    monkeypatch.setattr(web_app, "store", Store(tmp_path / "web.sqlite"))
    monkeypatch.setattr(web_app, "_check_web_auth", lambda: True)
    web_app.store.snapshot_course("77","Demo",[{
        "id":"2", "name":"Lab", "status":". не сдано", "deadline":"13.11.2026 23:59"
    }])
    with web_app.app.test_client() as client:
        for page in ("/calendar","/history","/files"):
            assert client.get(page).status_code == 200
        assert client.get("/api/calendar").get_json()["deadlines"][0]["name"] == "Lab"
        assert client.get("/api/history").get_json()["events"] == []
        assert client.get("/api/calendar.ics").status_code == 200
        assert client.get("/api/files").status_code == 200


def test_streamed_download_is_atomic(monkeypatch, tmp_path):
    import pgups_downloader as module
    monkeypatch.setattr(module, "COOKIES_FILE", tmp_path / "nonexistent")
    monkeypatch.setattr(module, "load_config", lambda: {"courses": []})
    dl = module.PgupsDownloader()
    data = b"file contents"
    class Response:
        headers = {"Content-Type":"application/pdf","Content-Length":str(len(data))}
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def raise_for_status(self): pass
        def iter_content(self, chunk_size): yield data
    monkeypatch.setattr(dl, "check_remote_size", lambda url:(len(data),None))
    monkeypatch.setattr(dl, "_trusted_file_request",lambda method,url,**kwargs:Response())
    url="https://sdo.pgups.ru/pluginfile.php/example"
    assert dl.download_file(url, "../sample.pdf", tmp_path)
    assert (tmp_path/"sample.pdf").read_bytes() == data
    assert not list(tmp_path.glob("*.part"))
    assert not dl.download_file(url, "sample.pdf", tmp_path)
