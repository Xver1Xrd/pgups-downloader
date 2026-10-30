#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import hashlib
import hmac
import secrets
import threading
import subprocess
from datetime import datetime
from urllib.parse import urlsplit, parse_qs
from pathlib import Path
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, render_template, request, session as flask_session, abort

sys.path.insert(0, str(Path(__file__).parent))
from pgups_downloader import (
    PgupsDownloader, BASE_URL, DOWNLOAD_BASE, DEFAULT_WORKERS,
    CONFIG_FILE, COOKIES_FILE, LOG_FILE,
    load_config, save_config, log,
)
from utils import count_statuses, cache_hash, clear_courses_cache
from secret_store import save_password, get_password
from storage import Store
from calendar_utils import create_ics, parse_deadline

# Persistent secret key: stored in a file so sessions survive restarts
_SECRET_KEY_FILE = Path(__file__).parent / ".secret_key"


def _load_secret_key() -> bytes:
    """Create Flask signing key with 0600 permissions from the first write."""
    if _SECRET_KEY_FILE.exists():
        try:
            _SECRET_KEY_FILE.chmod(0o600)
            key = _SECRET_KEY_FILE.read_bytes()
            if len(key) >= 32:
                return key
        except OSError:
            pass
    key = os.urandom(32)
    try:
        fd = os.open(_SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
    except FileExistsError:
        try:
            return _SECRET_KEY_FILE.read_bytes()
        except OSError:
            pass
    except OSError:
        pass
    return key

def _check_web_auth():
    """Optional HTTP Basic Auth via WEB_AUTH env var (format: 'user:password')."""
    auth_env = os.environ.get("WEB_AUTH", "")
    if not auth_env:
        return request.remote_addr in ("127.0.0.1", "::1")
    parts = auth_env.split(":", 1)
    if len(parts) != 2 or not all(parts):
        return False
    expected_user, expected_pass = parts
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        user, password = decoded.split(":", 1)
        return hmac.compare_digest(user, expected_user) and hmac.compare_digest(password, expected_pass)
    except Exception:
        return False


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _check_web_auth():
            from flask import make_response
            resp = make_response("Authentication required", 401)
            if os.environ.get("WEB_AUTH", ""):
                resp.headers["WWW-Authenticate"] = 'Basic realm="PGUPS"'
            return resp
        return f(*args, **kwargs)
    return decorated


app = Flask(__name__)
store = Store()
store.interrupt_unfinished_jobs()
app.secret_key = _load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

dl = PgupsDownloader()
courses_lock = threading.Lock()
auth_lock = threading.Lock()
last_check: dict[str, dict] = {}
check_lock = threading.Lock()
download_status = {"running": False, "message": "", "progress": ""}
download_lock = threading.Lock()
download_cancel = threading.Event()
_courses_cache = {"data": None, "time": 0}
CACHE_TTL = 300
_scheduler_lock = threading.Lock()
_scheduler_started = False


def notify_events(events: list[dict]):
    if not events or not load_config().get("desktop_notifications", False):
        return
    for event in events[:5]:
        try:
            subprocess.run(
                ["notify-send", "--app-name=PGUPS Downloader",
                 "Изменение в ЭИОС ПГУПС",
                 f"{event['course_name']}: {event['item_name']} — {event['new_status']}"],
                timeout=3, check=False, capture_output=True
            )
        except (OSError, subprocess.TimeoutExpired):
            return


def set_download_status(**changes):
    with download_lock:
        download_status.update(changes)
        snapshot = dict(download_status)
    job_id = snapshot.get("job_id")
    if job_id:
        try:
            parts = (snapshot.get("progress") or "0/0").split("/")
            done, total = int(parts[0]), int(parts[1])
            store.update_job(job_id, snapshot.get("state", "running"), total, done,
                             snapshot.get("downloaded",0),snapshot.get("skipped",0),
                             snapshot.get("failed",0))
        except (ValueError, IndexError, OSError) as exc:
            log(f"[JOBS] Ошибка обновления журнала: {exc}")


def start_scheduler():
    """Start an opt-in, rate-limited periodic grade sync in local web mode."""
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True
    def scheduler():
        last = 0.0
        while True:
            time.sleep(60)
            cfg = load_config()
            if not cfg.get("auto_sync", False):
                continue
            interval = max(15, int(cfg.get("sync_interval_minutes", 30) or 30))
            if time.monotonic() - last < interval * 60:
                continue
            last = time.monotonic()
            try:
                with auth_lock:
                    if not dl.verify_auth():
                        continue
                    cookies = list(dl.session.cookies)
                    headers = dict(dl.session.headers)
                with courses_lock:
                    courses = list(dl.courses)
                for course in courses:
                    fetch_one_course(course, cookies, headers)
                clear_courses_cache(_courses_cache)
            except Exception as exc:
                log(f"[SYNC] Ошибка фоновой проверки: {exc}")
    threading.Thread(target=scheduler, daemon=True, name="pgups-auto-sync").start()


def json_object() -> dict:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def get_creds() -> tuple[str, str]:
    cfg = load_config()
    login = cfg.get("login", "")
    password = get_password(login)
    if not password and cfg.get("password") and login:
        password = cfg["password"]
        try:
            save_password(login, password)
            cfg.pop("password", None)
            save_config(cfg)
        except RuntimeError:
            pass
    return login, password or ""


def ensure_auth():
    with auth_lock:
        if dl.verify_auth():
            return True
        login, password = get_creds()
        if login and password:
            ok = dl.login_via_portal(login, password)
            if ok:
                return True
        return False


def _load_course_names_parallel(courses_list: list[dict]) -> list[dict]:
    """Загрузка имён курсов параллельно."""
    if not courses_list:
        return []
    with ThreadPoolExecutor(max_workers=min(len(courses_list), 5)) as pool:
        futures = {
            pool.submit(dl.get_course_name, c["url"]): c
            for c in courses_list
        }
        result = []
        for f in futures:
            c = futures[f]
            try:
                name = f.result(timeout=15)
            except Exception:
                name = f"Курс {c['id']}"
            result.append({"id": c["id"], "url": c["url"], "name": name})
        return result


@app.before_request
@require_auth
def check_auth():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = flask_session.get("csrf", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not token or not hmac.compare_digest(token, supplied):
            abort(403)


@app.context_processor
def inject_csrf():
    if "csrf" not in flask_session:
        flask_session["csrf"] = secrets.token_urlsafe(32)
    return {"csrf_token": flask_session["csrf"]}


@app.after_request
def add_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/api/auth/status")
def api_auth_status():
    ok = dl.verify_auth()
    login, _ = get_creds()
    return jsonify({
        "authenticated": ok,
        "login": login if login else None,
    })


@app.route("/api/auth/captcha")
def api_auth_captcha():
    with auth_lock:
        data = dl.get_captcha()
        if data:
            # CAPTCHA and CSRF token are bound to the portal cookie/session.
            # The subsequent login POST may run on a different Flask worker.
            dl.publish_session_cookies()
    if not data:
        return jsonify({"error": "Не удалось загрузить страницу входа"}), 502
    captcha_b64 = base64.b64encode(data["captcha_data"]).decode() if data.get("captcha_data") else ""
    return jsonify({
        "csrf_token": data["csrf_token"],
        "captcha_b64": captcha_b64,
        "captcha_url": data.get("captcha_url", ""),
    })


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = json_object()
    if any(not isinstance(data.get(k, ""), str) for k in ("email","password","captcha","csrf_token")):
        return jsonify({"error":"Некорректные параметры авторизации"}), 400
    email = data.get("email", "").strip()
    password = data.get("password", "")
    captcha = data.get("captcha", "").strip()
    csrf_token = data.get("csrf_token", "").strip()
    remember = data.get("remember", False)

    login, pwd = email or get_creds()[0], password or get_creds()[1]
    with auth_lock:
        if dl.verify_auth():
            return jsonify({"authenticated": True})
        ok = dl.login_via_portal(login, pwd, captcha, remember, csrf_token)
        if ok:
            return jsonify({"authenticated": True})
        return jsonify({"authenticated": False, "error": "Неверный логин, пароль или капча"})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/download")
def download_page():
    with courses_lock:
        cfg_courses = list(dl.courses)
    courses_with_names = _load_course_names_parallel(cfg_courses)
    return render_template("download.html", courses=courses_with_names, default_workers=DEFAULT_WORKERS)


@app.route("/course/<course_id>")
def course_page(course_id):
    return render_template("course.html", course_id=course_id)


@app.route("/add-course")
def add_course_page():
    return render_template("add_course.html")


@app.route("/settings")
def settings_page():
    with courses_lock:
        cfg_courses = list(dl.courses)
    courses_with_names = _load_course_names_parallel(cfg_courses)
    return render_template("settings.html", courses=courses_with_names, login=load_config().get("login"))


def fetch_one_course(course: dict, cookies: list = None, headers: dict = None) -> dict | None:
    try:
        tmp_dl = PgupsDownloader(courses=dl.courses)
        if cookies:
            for c in cookies:
                tmp_dl.session.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
        if headers:
            tmp_dl.session.headers.update(headers)
        rows, name = tmp_dl.check_course(course["url"])
    except Exception as e:
        return {"id": course["id"], "name": f"Ошибка: {e}", "error": True}
    events = store.snapshot_course(str(course["id"]), name, rows)
    notify_events(events)
    stats = count_statuses(rows)
    stats["items"] = rows
    stats["url"] = course["url"]
    stats["name"] = name
    stats["id"] = course["id"]
    return stats


@app.route("/api/courses")
def api_courses():
    now = time.time()
    with courses_lock:
        courses_snapshot = list(dl.courses)
    cache_key = cache_hash(courses_snapshot)
    if _courses_cache.get("_key") == cache_key and _courses_cache["data"] and now - _courses_cache["time"] < CACHE_TTL:
        return jsonify(_courses_cache["data"])

    ok = ensure_auth()
    if not ok:
        configured_ids = {c["id"] for c in courses_snapshot}
        cached = [c for c in store.cached_courses() if c["id"] in configured_ids]
        result = {"courses": cached if cached else [{"id": c["id"], "name": "Нет авторизации", "error": True} for c in courses_snapshot], "offline": bool(cached)}
        # Never cache offline/auth failures for 5 minutes: reconnect immediately.
        return jsonify(result)

    cookies = list(dl.session.cookies)
    headers = dict(dl.session.headers)
    results = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        fut = {pool.submit(fetch_one_course, c, cookies, headers): c for c in courses_snapshot}
        for f in as_completed(fut):
            try:
                r = f.result(timeout=30)
                if r:
                    results.append(r)
            except Exception:
                c = fut[f]
                results.append({"id": c["id"], "name": f"Курс {c['id']}", "error": True})

    # Prefer a last-known-good snapshot when one remote course fails.
    cached_by_id = {c["id"]:c for c in store.cached_courses()}
    results = [cached_by_id.get(r["id"], r) if r.get("error") else r for r in results]
    # Stable presentation order, and persistent events are derived by Store.
    by_id = {r["id"]:r for r in results}
    results = [by_id[c["id"]] for c in courses_snapshot if c["id"] in by_id]

    data = {"courses": results}
    _courses_cache["data"] = data
    _courses_cache["time"] = now
    _courses_cache["_key"] = cache_key
    return jsonify(data)


@app.route("/api/course/<course_id>")
def api_course(course_id):
    ok = ensure_auth()
    if not ok:
        with courses_lock:
            allowed = any(c["id"] == course_id for c in dl.courses)
        cached = next((c for c in store.cached_courses() if c["id"] == course_id), None) if allowed else None
        if cached:
            return jsonify(cached)
        return jsonify({"error": "Нет авторизации"}), 401
    with courses_lock:
        course = next((c for c in dl.courses if c["id"] == course_id), None)
    if not course:
        return jsonify({"error": "Курс не найден"}), 404
    try:
        rows, name = dl.check_course(course["url"])
    except Exception as e:
        cached = next((c for c in store.cached_courses() if c["id"] == course_id), None)
        if cached:
            return jsonify(cached)
        return jsonify({"error": str(e)}), 502
    events = store.snapshot_course(str(course_id), name, rows)
    notify_events(events)
    stats = count_statuses(rows)
    stats["id"] = course_id
    stats["name"] = name
    stats["items"] = rows
    return jsonify(stats)


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/calendar")
def calendar_page():
    return render_template("calendar.html")


@app.route("/files")
def files_page():
    return render_template("files.html")


@app.route("/api/history")
def api_history():
    return jsonify({"events": store.history()})


@app.route("/api/calendar")
def api_calendar():
    items = store.deadlines()
    for item in items:
        parsed = parse_deadline(item.get("deadline"))
        item["deadline_iso"] = parsed.isoformat() if parsed else None
    return jsonify({"deadlines": items})


@app.route("/api/calendar.ics")
def api_calendar_ics():
    from flask import Response
    return Response(create_ics(store.deadlines()), content_type="text/calendar; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=pgups-deadlines.ics"})


@app.route("/api/files")
def api_files():
    return jsonify({"files": store.downloaded_files()})


@app.route("/api/settings/automation", methods=["GET", "POST"])
def api_automation():
    cfg = load_config()
    if request.method == "GET":
        return jsonify({"auto_sync": cfg.get("auto_sync", False),
                        "sync_interval_minutes": cfg.get("sync_interval_minutes", 30),
                        "desktop_notifications": cfg.get("desktop_notifications", False)})
    data = json_object()
    minutes = data.get("sync_interval_minutes", 30)
    if type(minutes) is not int or not 15 <= minutes <= 1440:
        return jsonify({"error": "Интервал синхронизации: от 15 до 1440 минут"}), 400
    if any(type(data.get(key)) is not bool for key in ("auto_sync", "desktop_notifications")):
        return jsonify({"error": "Некорректные настройки"}), 400
    cfg.update(auto_sync=data["auto_sync"], sync_interval_minutes=minutes,
               desktop_notifications=data["desktop_notifications"])
    save_config(cfg)
    return jsonify({"status": "ok"})


@app.route("/api/download", methods=["POST"])
def api_download():
    ok = ensure_auth()
    if not ok:
        return jsonify({"error": "Нет авторизации"}), 401
    data = json_object()
    course_ids = data.get("course_ids", [])
    download_type = data.get("download_type", "both")
    try:
        workers = int(data.get("workers", DEFAULT_WORKERS))
    except (ValueError, TypeError):
        return jsonify({"error": "Некорректное количество потоков"}), 400
    if not 1 <= workers <= 10 or download_type not in ("both", "submission", "attachment"):
        return jsonify({"error": "Недопустимые параметры загрузки"}), 400
    if not isinstance(course_ids, list) or any(not isinstance(x, str) for x in course_ids):
        return jsonify({"error": "Некорректный список курсов"}), 400

    with courses_lock:
        if course_ids:
            courses = [c for c in dl.courses if c["id"] in course_ids]
        else:
            courses = list(dl.courses)

    if not courses:
        return jsonify({"error": "Курсы не найдены"}), 404

    with download_lock:
        if download_status["running"]:
            return jsonify({"error": "Скачивание уже выполняется"}), 409
        download_cancel.clear()
        job_id = secrets.token_hex(12)
        store.create_job(job_id)
        download_status.update(job_id=job_id, state="preparing", running=True,
                               message="Запуск...", progress="", downloaded=0,
                               skipped=0, failed=0, cancelled=False)

    def run_dl():
        worker_dl = PgupsDownloader(courses=courses)
        worker_dl.session.cookies.update(dl.session.cookies)
        worker_dl.workers = workers
        try:
            log(f"\n[WEB] Скачивание {len(courses)} курсов ({workers} потоков)")
            set_download_status(message="Сбор заданий...", state="preparing")
            tasks = worker_dl.collect_tasks(download_type=download_type)
            if not tasks:
                set_download_status(message="Нет файлов для скачивания", progress="0/0", state="complete")
            else:
                set_download_status(message=f"Скачивание {len(tasks)} файлов...",
                                    progress=f"0/{len(tasks)}",state="running")
                downloaded = 0
                failed = 0
                skipped = 0
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    fut = {pool.submit(worker_dl.download_file, url, name, folder, cancel_event=download_cancel): (url, name, folder)
                           for url, name, folder in tasks}
                    total = len(fut)
                    for done, f in enumerate(as_completed(fut), 1):
                        url, name, folder = fut[f]
                        try:
                            success = f.result()
                            status = "downloaded" if success else ("skipped" if (folder / name).is_file() else "failed")
                        except Exception as exc:
                            log(f"[WEB] Ошибка файла {name}: {exc}")
                            status = "failed"
                        if status == "downloaded":
                            downloaded += 1
                        elif status == "skipped":
                            skipped += 1
                        else:
                            failed += 1
                        store.record_download(url, name, str(folder / name), status, folder.parent.name)
                        set_download_status(progress=f"{done}/{total}", downloaded=downloaded, skipped=skipped, failed=failed)
                message = (f"Отменено: {downloaded} загружено, {skipped} пропущено, {failed} ошибок"
                           if download_cancel.is_set() else
                           f"Готово: {downloaded} загружено, {skipped} пропущено, {failed} ошибок")
                set_download_status(message=message, progress=f"{total}/{total}",
                                    cancelled=download_cancel.is_set(),
                                    state="cancelled" if download_cancel.is_set() else "complete")
        except Exception as e:
            log(f"[WEB] Ошибка скачивания: {e}")
            set_download_status(message=f"Ошибка: {e}",state="failed")
        finally:
            set_download_status(running=False,
                                state=("cancelled" if download_cancel.is_set() else
                                       download_status.get("state","failed")))

    t = threading.Thread(target=run_dl, daemon=True)
    t.start()
    return jsonify({"status": "started", "job_id": job_id})


@app.route("/api/download/jobs")
def api_download_jobs():
    return jsonify({"jobs":store.recent_jobs()})


@app.route("/api/download/cancel", methods=["POST"])
def api_download_cancel():
    with download_lock:
        if not download_status["running"]:
            return jsonify({"error":"Нет активной загрузки"}), 409
        download_cancel.set()
        download_status["message"] = "Отмена загрузки..."
        download_status["state"] = "cancelling"
    return jsonify({"status":"cancelling"})


@app.route("/api/download/status")
def api_download_status():
    with download_lock:
        return jsonify(dict(download_status))


@app.route("/api/settings/login", methods=["POST"])
def api_settings_login():
    data = json_object()
    if not isinstance(data.get("login", ""), str) or not isinstance(data.get("password", ""), str):
        return jsonify({"error":"Некорректный логин или пароль"}), 400
    login = data.get("login", "").strip()
    password = data.get("password", "")
    cfg = load_config()
    if login:
        cfg["login"] = login
    if password:
        if not (login or cfg.get("login", "")):
            return jsonify({"error": "Укажите логин перед сохранением пароля"}), 400
        try:
            save_password(login or cfg.get("login", ""), password)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503
        cfg.pop("password", None)
    save_config(cfg)
    log("[WEB] Логин/пароль сохранены")
    clear_courses_cache(_courses_cache)
    return jsonify({"status": "ok"})


@app.route("/api/courses/discover", methods=["POST"])
def api_discover_courses():
    if not ensure_auth():
        return jsonify({"error":"Авторизация в ЭИОС не выполнена"}), 401
    discovered = dl.discover_courses()
    if not discovered:
        return jsonify({"error":"Не удалось найти курсы; добавьте их вручную"}), 404
    with courses_lock:
        saved = list(dl.courses)
        existing_ids = {c["id"] for c in saved}
        for course in discovered:
            if course["id"] not in existing_ids:
                saved.append(course)
                existing_ids.add(course["id"])
        cfg = load_config()
        cfg["courses"] = saved
        save_config(cfg)
        dl.courses = saved
    clear_courses_cache(_courses_cache)
    return jsonify({"status":"ok","discovered":len(discovered),"total":len(saved)})


@app.route("/api/settings/courses", methods=["GET", "POST", "DELETE"])
def api_settings_courses():
    cfg = load_config()
    with courses_lock:
        courses = list(dl.courses)

    if request.method == "GET":
        result = _load_course_names_parallel(courses)
        return jsonify({"courses": result})

    if request.method == "POST":
        data = json_object()
        url = data.get("url", "")
        if not isinstance(url, str):
            return jsonify({"error":"Некорректный URL"}), 400
        url = url.strip()
        if url.isascii() and url.isdigit():
            url = f"{BASE_URL}/course/view.php?id={url}"
        try:
            parsed = urlsplit(url)
            valid = (parsed.scheme == "https" and parsed.hostname == "sdo.pgups.ru"
                     and not parsed.username and not parsed.password
                     and parsed.port in (None, 443) and parsed.path == "/course/view.php")
        except ValueError:
            valid = False
        if not valid:
            return jsonify({"error": "Разрешены только ссылки на курсы sdo.pgups.ru"}), 400
        course_id = parse_qs(parsed.query).get("id", [""])[0]
        if not course_id.isascii() or not course_id.isdigit():
            return jsonify({"error": "Некорректный ID курса"}), 400
        url = f"{BASE_URL}/course/view.php?id={course_id}"
        new = {"id": course_id, "url": url}
        if any(c["id"] == course_id for c in courses):
            return jsonify({"error": "Курс уже добавлен"}), 409
        courses.append(new)
        cfg["courses"] = courses
        save_config(cfg)
        with courses_lock:
            dl.courses = list(courses)
        log(f"[WEB] Курс {course_id} добавлен")
        clear_courses_cache(_courses_cache)
        return jsonify({"status": "ok", "id": course_id})

    if request.method == "DELETE":
        data = json_object()
        course_id = data.get("id")
        courses = [c for c in courses if c["id"] != course_id]
        cfg["courses"] = courses
        save_config(cfg)
        with courses_lock:
            dl.courses = list(courses)
        log(f"[WEB] Курс {course_id} удалён")
        clear_courses_cache(_courses_cache)
        return jsonify({"status": "ok"})


@app.route("/api/settings/logs", methods=["DELETE"])
def api_clear_logs():
    if LOG_FILE.exists():
        try:
            LOG_FILE.unlink()
        except OSError:
            pass
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    login, password = get_creds()
    if login and password:
        ensure_auth()
    port = int(os.environ.get("PORT", 5000))
    log(f"[WEB] Сервер запущен на http://127.0.0.1:{port}")
    start_scheduler()
    app.run(host="127.0.0.1", port=port, debug=False)
