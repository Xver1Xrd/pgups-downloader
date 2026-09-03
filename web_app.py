#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import hashlib
import threading
import signal
from pathlib import Path
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, render_template, request, session as flask_session

sys.path.insert(0, str(Path(__file__).parent))
from pgups_downloader import (
    PgupsDownloader, BASE_URL, DOWNLOAD_BASE, DEFAULT_WORKERS,
    CONFIG_FILE, COOKIES_FILE, LOG_FILE,
    load_config, save_config, log,
)
from utils import count_statuses, cache_hash, clear_courses_cache

# Persistent secret key: stored in a file so sessions survive restarts
_SECRET_KEY_FILE = Path(__file__).parent / ".secret_key"

# HTTP Basic Auth (enabled by default via PGUPS_AUTH env)
_AUTH_ENABLED = os.environ.get("PGUPS_AUTH", "1") != "0"
_AUTH_USER = os.environ.get("PGUPS_AUTH_USER", "")
_AUTH_PASS = os.environ.get("PGUPS_AUTH_PASS", "")

# Rate limiting: track recent requests per IP
_rate_limit_lock = threading.Lock()
_rate_limit_window = 60
_rate_limit_max = 30
_request_log: dict[str, list[float]] = {}

# CSRF protection
_csrf_lock = threading.Lock()
_csrf_tokens: dict[str, tuple[str, float]] = {}  # user_token -> (value, timestamp)
CSRF_TTL = 3600  # 1 hour

# Config cache to avoid repeated disk reads
_config_cache = {"data": None, "time": 0, "ttl": 30}
_config_cache_lock = threading.Lock()


def _load_secret_key() -> bytes:
    if _SECRET_KEY_FILE.exists():
        try:
            return _SECRET_KEY_FILE.read_bytes()
        except OSError:
            pass
    key = os.urandom(32)
    try:
        _SECRET_KEY_FILE.write_bytes(key)
    except OSError:
        pass
    return key


def _check_web_auth():
    """HTTP Basic Auth - required by default unless PGUPS_AUTH=0."""
    if not _AUTH_ENABLED:
        return True
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        user, password = decoded.split(":", 1)
        return user == _AUTH_USER and password == _AUTH_PASS
    except Exception:
        return False


def _check_rate_limit() -> bool:
    """Return True if request is allowed."""
    now = time.time()
    ip = request.remote_addr or "127.0.0.1"
    with _rate_limit_lock:
        if ip not in _request_log:
            _request_log[ip] = []
        # Remove old entries
        _request_log[ip] = [t for t in _request_log[ip] if now - t < _rate_limit_window]
        if len(_request_log[ip]) >= _rate_limit_max:
            return False
        _request_log[ip].append(now)
        return True


def _generate_csrf_token() -> str:
    """Generate a CSRF token for the current session."""
    import secrets
    token = secrets.token_hex(32)
    now = time.time()
    with _csrf_lock:
        # Clean old tokens
        global _csrf_tokens
        _csrf_tokens = {k: v for k, v in _csrf_tokens.items() if now - v[1] < CSRF_TTL}
    _csrf_tokens[token] = (token, now)
    return token


def _validate_csrf_token(token: str) -> bool:
    """Validate a CSRF token."""
    if not token:
        return False
    now = time.time()
    with _csrf_lock:
        global _csrf_tokens
        # Clean old tokens
        _csrf_tokens = {k: v for k, v in _csrf_tokens.items() if now - v[1] < CSRF_TTL}
        stored = _csrf_tokens.pop(token, None)
        if stored is None:
            return False
        return now - stored[1] < CSRF_TTL


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _check_web_auth():
            from flask import make_response
            resp = make_response("Authentication required", 401)
            resp.headers["WWW-Authenticate"] = 'Basic realm="PGUPS"'
            return resp
        if not _check_rate_limit():
            from flask import make_response
            return make_response("Too many requests. Try again later.", 429)
        # Validate CSRF for POST/PUT/DELETE requests
        if request.method in ("POST", "PUT", "DELETE"):
            csrf_token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not _validate_csrf_token(csrf_token):
                from flask import make_response
                return make_response("CSRF token invalid or expired", 403)
        return f(*args, **kwargs)
    return decorated


app = Flask(__name__)
app.secret_key = _load_secret_key()

dl = PgupsDownloader()
courses_lock = threading.Lock()
auth_lock = threading.Lock()
last_check: dict[str, dict] = {}
check_lock = threading.Lock()
download_status = {"running": False, "message": "", "progress": ""}
download_lock = threading.Lock()
_courses_cache = {"data": None, "time": 0, "stale": None, "stale_time": 0}
CACHE_TTL = 600
AUTH_CACHE_TTL = 120
_auth_cache = {"authenticated": None, "time": 0}


def _load_config_cached() -> dict:
    """Load config with 30-second cache to avoid repeated disk reads."""
    now = time.time()
    with _config_cache_lock:
        if (
            _config_cache["data"] is not None
            and now - _config_cache["time"] < _config_cache["ttl"]
        ):
            return _config_cache["data"]
        try:
            data = load_config()
            _config_cache["data"] = data
            _config_cache["time"] = now
            return data
        except Exception:
            if _config_cache["data"] is None:
                return {}
            return _config_cache["data"]


def invalidate_config_cache():
    """Invalidate config cache (called after settings change)."""
    with _config_cache_lock:
        _config_cache["data"] = None
        _config_cache["time"] = 0


def get_creds() -> tuple[str, str]:
    cfg = _load_config_cached()
    return cfg.get("login", ""), cfg.get("password", "")


def _is_auth_cached() -> bool:
    now = time.time()
    return _auth_cache["authenticated"] is not None and now - _auth_cache["time"] < AUTH_CACHE_TTL


def _get_auth_status() -> bool:
    now = time.time()
    if _is_auth_cached():
        return _auth_cache["authenticated"]
    result = dl.verify_auth()
    _auth_cache["authenticated"] = result
    _auth_cache["time"] = now
    return result


def ensure_auth():
    with auth_lock:
        if _get_auth_status():
            return True
        login, password = get_creds()
        if login and password:
            ok = dl.login_via_portal(login, password)
            if ok:
                _auth_cache["authenticated"] = True
                _auth_cache["time"] = time.time()
                return True
        _auth_cache["authenticated"] = False
        _auth_cache["time"] = time.time()
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
    pass


@app.after_request
def add_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/api/csrf-token")
def api_csrf_token():
    """Generate and return a CSRF token for the client."""
    token = _generate_csrf_token()
    return jsonify({"csrf_token": token})


@app.route("/api/auth/status")
def api_auth_status():
    authenticated = _get_auth_status()
    login, _ = get_creds()
    return jsonify({
        "authenticated": authenticated,
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
    data = request.get_json()
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
    cfg = _load_config_cached()
    return render_template("settings.html", courses=courses_with_names, login=cfg.get("login"))


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

    # Serve stale data while refreshing
    is_stale = (
        _courses_cache.get("_key") == cache_key
        and _courses_cache["stale"] is not None
        and now - _courses_cache["stale_time"] < CACHE_TTL * 2
    )

    if is_stale:
        # Return stale cache immediately, refresh in background
        threading.Thread(target=_refresh_courses, args=(courses_snapshot,), daemon=True).start()
        return jsonify(_courses_cache["stale"])

    if _courses_cache.get("_key") == cache_key and _courses_cache["data"] and now - _courses_cache["time"] < CACHE_TTL:
        return jsonify(_courses_cache["data"])

    _do_refresh_courses(courses_snapshot)
    return jsonify(_courses_cache["data"] or {"courses": []})


def _do_refresh_courses(courses_snapshot: list):
    now = time.time()
    try:
        ok = ensure_auth()
        if not ok:
            result = {"courses": [{"id": c["id"], "name": "Нет авторизации", "error": True} for c in courses_snapshot]}
            _courses_cache["data"] = result
            _courses_cache["time"] = now
            _courses_cache["_key"] = cache_hash(courses_snapshot)
            return

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
        _courses_cache["stale"] = _courses_cache["data"]
        _courses_cache["stale_time"] = now
        _courses_cache["data"] = data
        _courses_cache["time"] = now
        _courses_cache["_key"] = cache_hash(courses_snapshot)
    except Exception as e:
        log(f"[WEB] Ошибка обновления кэша курсов: {e}")
        # Don't invalidate cache on error - keep stale data


def _refresh_courses(courses_snapshot: list):
    try:
        _do_refresh_courses(courses_snapshot)
    except Exception:
        pass


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
    data = request.get_json()
    course_ids = data.get("course_ids", [])
    workers = data.get("workers", DEFAULT_WORKERS)
    download_type = data.get("download_type", "both")

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

    # Store original values under lock before starting thread
    with courses_lock:
        original_courses = list(dl.courses)
    original_workers = dl.workers
    download_type_local = download_type

    def run_dl():
        nonlocal original_workers
        with courses_lock:
            dl.courses = courses
        dl.workers = workers
        try:
            log(f"\n[WEB] Скачивание {len(courses)} курсов ({workers} потоков)")
            download_status["message"] = "Сбор заданий..."
            tasks = dl.collect_tasks(download_type=download_type_local)
            if not tasks:
                download_status["message"] = "Нет файлов для скачивания"
                download_status["progress"] = "0/0"
            else:
                download_status["message"] = f"Скачивание {len(tasks)} файлов..."
                downloaded = 0
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    fut = {pool.submit(dl.download_file, url, name, folder): name
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
            with courses_lock:
                dl.courses = original_courses
            dl.workers = original_workers
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
    data = request.get_json()
    login = data.get("login", "").strip()
    password = data.get("password", "").strip()
    cfg = _load_config_cached()
    if login:
        cfg["login"] = login
    if password:
        cfg["password"] = password
    save_config(cfg)
    # Invalidate config cache
    invalidate_config_cache()
    log("[WEB] Логин/пароль сохранены")
    clear_courses_cache(_courses_cache)
    return jsonify({"status": "ok"})


@app.route("/api/settings/courses", methods=["GET", "POST", "DELETE"])
def api_settings_courses():
    cfg = _load_config_cached()
    with courses_lock:
        courses = list(dl.courses)

    if request.method == "GET":
        result = _load_course_names_parallel(courses)
        return jsonify({"courses": result})

    if request.method == "POST":
        data = request.get_json()
        url = data.get("url", "").strip()
        if url.isdigit():
            url = f"{BASE_URL}/course/view.php?id={url}"
        elif "course/view.php?id=" not in url:
            return jsonify({"error": "Неверный формат"}), 400
        course_id = url.split("=")[-1].split("&")[0]
        new = {"id": course_id, "url": url}
        if new in courses:
            return jsonify({"error": "Курс уже добавлен"}), 409
        courses.append(new)
        cfg["courses"] = courses
        save_config(cfg)
        with courses_lock:
            dl.courses = list(courses)
            dl.config["courses"] = list(courses)
        log(f"[WEB] Курс {course_id} добавлен")
        clear_courses_cache(_courses_cache)
        return jsonify({"status": "ok", "id": course_id})

    if request.method == "DELETE":
        data = request.get_json()
        course_id = data.get("id")
        courses = [c for c in courses if c["id"] != course_id]
        cfg["courses"] = courses
        save_config(cfg)
        with courses_lock:
            dl.courses = list(courses)
            dl.config["courses"] = list(courses)
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


def _preload_cache():
    global _preload_started
    if _preload_started:
        return
    _preload_started = True
    time.sleep(2)
    try:
        with courses_lock:
            snapshot = list(dl.courses)
        _do_refresh_courses(snapshot)
        log("[WEB] Кэш предзагружен")
    except Exception as e:
        log(f"[WEB] Ошибка предзагрузки кэша: {e}")


# Preload cache when module is imported
threading.Thread(target=_preload_cache, daemon=True).start()


def _signal_handler(signum, frame):
    """Graceful shutdown handler."""
    log("[WEB] Получен сигнал завершения, ожидаем потоки...")
    # Wait for download thread to finish
    while download_status["running"]:
        time.sleep(0.5)
    sys.exit(0)


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


if __name__ == "__main__":
    login, password = get_creds()
    if login and password:
        ensure_auth()
    port = int(os.environ.get("PORT", 5000))
    log(f"[WEB] Сервер запущен на http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
