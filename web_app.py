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

# Persistent secret key: stored in a file so sessions survive restarts
_SECRET_KEY_FILE = Path(__file__).parent / ".secret_key"


def _load_secret_key() -> bytes:
    if _SECRET_KEY_FILE.exists():
        try:
            return _SECRET_KEY_FILE.read_bytes()
        except OSError:
            pass
    key = os.urandom(32)
    try:
        _SECRET_KEY_FILE.write_bytes(key)
        _SECRET_KEY_FILE.chmod(0o600)
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
            auth_env = os.environ.get("WEB_AUTH", "")
            if auth_env:
                from flask import make_response
                resp = make_response("Authentication required", 401)
                resp.headers["WWW-Authenticate"] = 'Basic realm="PGUPS"'
                return resp
        return f(*args, **kwargs)
    return decorated


app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

dl = PgupsDownloader()
courses_lock = threading.Lock()
auth_lock = threading.Lock()
last_check: dict[str, dict] = {}
check_lock = threading.Lock()
download_status = {"running": False, "message": "", "progress": ""}
download_lock = threading.Lock()
_courses_cache = {"data": None, "time": 0}
CACHE_TTL = 300


def get_creds() -> tuple[str, str]:
    cfg = load_config()
    login = cfg.get("login", "")
    return login, get_password(login) or cfg.get("password", "")


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
    data = dl.get_captcha()
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
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
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
        result = {"courses": [{"id": c["id"], "name": "Нет авторизации", "error": True} for c in courses_snapshot]}
        _courses_cache["data"] = result
        _courses_cache["time"] = now
        _courses_cache["_key"] = cache_key
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

    with check_lock:
        prev = dict(last_check)
        last_check.clear()
        for r in results:
            if r.get("error"):
                continue
            key = r["id"]
            items = r.get("items", [])
            last_check[key] = {i["name"]: i["status"] for i in items}
            if key in prev:
                old = prev[key]
                for item in items:
                    if item["name"] in old and old[item["name"]] != item["status"]:
                        item["changed"] = True
                        item["prev_status"] = old[item["name"]]

    data = {"courses": results}
    _courses_cache["data"] = data
    _courses_cache["time"] = now
    _courses_cache["_key"] = cache_key
    return jsonify(data)


@app.route("/api/course/<course_id>")
def api_course(course_id):
    ok = ensure_auth()
    if not ok:
        return jsonify({"error": "Нет авторизации"}), 401
    with courses_lock:
        course = next((c for c in dl.courses if c["id"] == course_id), None)
    if not course:
        return jsonify({"error": "Курс не найден"}), 404
    try:
        rows, name = dl.check_course(course["url"])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    stats = count_statuses(rows)
    stats["id"] = course_id
    stats["name"] = name
    stats["items"] = rows
    return jsonify(stats)


@app.route("/api/download", methods=["POST"])
def api_download():
    ok = ensure_auth()
    if not ok:
        return jsonify({"error": "Нет авторизации"}), 401
    data = request.get_json(silent=True) or {}
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
        download_status["running"] = True
        download_status["message"] = "Запуск..."
        download_status["progress"] = ""

    def run_dl():
        worker_dl = PgupsDownloader(courses=courses)
        worker_dl.session.cookies.update(dl.session.cookies)
        worker_dl.workers = workers
        try:
            log(f"\n[WEB] Скачивание {len(courses)} курсов ({workers} потоков)")
            download_status["message"] = "Сбор заданий..."
            tasks = worker_dl.collect_tasks(download_type=download_type)
            if not tasks:
                download_status["message"] = "Нет файлов для скачивания"
                download_status["progress"] = "0/0"
            else:
                download_status["message"] = f"Скачивание {len(tasks)} файлов..."
                downloaded = 0
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    fut = {pool.submit(worker_dl.download_file, url, name, folder): name
                           for url, name, folder in tasks}
                    total = len(fut)
                    for f in as_completed(fut):
                        if f.result():
                            downloaded += 1
                        done = sum(1 for ff in fut if ff.done())
                        download_status["progress"] = f"{done}/{total}"
                download_status["message"] = f"Готово! Скачано: {downloaded}, пропущено: {total - downloaded}"
                download_status["progress"] = f"{total}/{total}"
        except Exception as e:
            log(f"[WEB] Ошибка скачивания: {e}")
            download_status["message"] = f"Ошибка: {e}"
        finally:
            with download_lock:
                download_status["running"] = False

    t = threading.Thread(target=run_dl, daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/api/download/status")
def api_download_status():
    with download_lock:
        return jsonify(dict(download_status))


@app.route("/api/settings/login", methods=["POST"])
def api_settings_login():
    data = request.get_json(silent=True) or {}
    login = data.get("login", "").strip()
    password = data.get("password", "").strip()
    cfg = load_config()
    if login:
        cfg["login"] = login
    if password:
        save_password(login or cfg.get("login", ""), password)
        cfg.pop("password", None)
    save_config(cfg)
    log("[WEB] Логин/пароль сохранены")
    clear_courses_cache(_courses_cache)
    return jsonify({"status": "ok"})


@app.route("/api/settings/courses", methods=["GET", "POST", "DELETE"])
def api_settings_courses():
    cfg = load_config()
    with courses_lock:
        courses = list(dl.courses)

    if request.method == "GET":
        result = _load_course_names_parallel(courses)
        return jsonify({"courses": result})

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        url = data.get("url", "").strip()
        if url.isdigit():
            url = f"{BASE_URL}/course/view.php?id={url}"
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "sdo.pgups.ru" or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.path != "/course/view.php":
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
        data = request.get_json(silent=True) or {}
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
    app.run(host="127.0.0.1", port=port, debug=False)
