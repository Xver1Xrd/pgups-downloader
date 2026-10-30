"""Fixture-driven checks of Moodle HTML and authentication handling."""
from pathlib import Path
import pytest

from pgups_downloader import PgupsDownloader

COURSE_HTML = """
<h1>Тестовая дисциплина</h1>
<ul><li class="activity" data-id="20">
  <div class="availabilityinfo">Недоступно до завершения предыдущего задания</div>
  <span class="instancename">Работа 2</span></li></ul>
"""
GRADES_HTML = """
<table class="generaltable">
<tr><td><a href="/mod/assign/view.php?id=10">Задание Работа 1</a></td><td>-</td><td>Отл (5,00)</td></tr>
<tr><td><a href="/mod/assign/view.php?id=20">Задание Работа 2</a></td><td>-</td><td>-</td></tr>
<tr><td><a href="/mod/assign/view.php?id=30">Задание Работа 3</a></td><td>-</td><td>-</td></tr>
<tr><td><a href="/mod/quiz/view.php?id=40">Тест Контроль</a></td><td>-</td><td>-</td></tr>
</table>
"""

@pytest.fixture
def downloader(monkeypatch,tmp_path):
    import pgups_downloader as m
    monkeypatch.setattr(m,"COOKIES_FILE",tmp_path/"missing")
    monkeypatch.setattr(m,"load_config",lambda:{"courses":[]})
    return PgupsDownloader()


def test_grade_html_parsing_and_deadlines(monkeypatch,downloader):
    class Response:
        def __init__(self,text): self.text = text
        def raise_for_status(self): pass
    def get(url,**kwargs):
        if "grade/report" in url: return Response(GRADES_HTML)
        return Response(COURSE_HTML)
    monkeypatch.setattr(downloader,"get",get)
    monkeypatch.setattr(downloader,"_check_submission_and_deadline",
                        lambda url:(True,"13.11.2026 23:59"))
    items, name = downloader.check_course("https://sdo.pgups.ru/course/view.php?id=42")
    assert name == "Тестовая дисциплина"
    by_id = {i["id"]:i for i in items}
    assert by_id["10"]["status"].startswith("+")
    assert by_id["20"]["status"].startswith("#")
    assert by_id["30"]["status"].startswith("~")
    assert by_id["30"]["deadline"] == "13.11.2026 23:59"
    assert by_id["40"]["status"].startswith(".")


@pytest.mark.parametrize("url,body,expected",[
    ("https://sdo.pgups.ru/my/","<div class='usermenu'>profile</div>",True),
    ("https://sdo.pgups.ru/login/index.php","<div class='usermenu'>profile</div>",False),
    ("https://sdo.pgups.ru/my/","<p>Гостевой доступ</p>",False),
    ("https://sdo.pgups.ru/my/","<form action='/login/index.php'></form>",False),
    ("https://evil.example/my/","<div class='usermenu'>profile</div>",False),
])
def test_authentication_markers(monkeypatch,downloader,url,body,expected):
    class Response:
        status_code = 200
        text = body
        def __init__(self,url): self.url=url
    monkeypatch.setattr(downloader,"get",lambda *args,**kwargs: Response(url))
    assert downloader.verify_auth() is expected


def test_partial_download_is_rejected(monkeypatch,downloader,tmp_path):
    class Response:
        headers = {"Content-Type":"application/pdf","Content-Length":"100"}
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def raise_for_status(self): pass
        def iter_content(self,chunk_size): yield b"short"
    monkeypatch.setattr(downloader,"_trusted_file_request",lambda method,url,**kwargs:Response())
    monkeypatch.setattr(downloader,"check_remote_size",lambda url:(None,None))
    assert not downloader.download_file("https://sdo.pgups.ru/pluginfile.php/1","truncated.pdf",tmp_path,max_retries=1)
    assert not (tmp_path/"truncated.pdf").exists()
    assert not list(tmp_path.glob("*.part"))


def test_reject_bad_download_options(monkeypatch):
    import web_app
    monkeypatch.setattr(web_app,"_check_web_auth",lambda:True)
    monkeypatch.setattr(web_app,"ensure_auth",lambda:True)
    with web_app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["csrf"]="token"
        for workers in (0,-1,100,"bad"):
            response=client.post("/api/download",json={"workers":workers},
                                 headers={"X-CSRF-Token":"token"})
            assert response.status_code == 400
