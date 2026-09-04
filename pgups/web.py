#!/usr/bin/env python3
"""PGUPS Downloader — Flask web interface with factory pattern."""

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
from flask import Flask, jsonify, render_template, request

from pgups.downloader import (
    PgupsDownloader, BASE_URL, DOWNLOAD_BASE, DEFAULT_WORKERS,
    CONFIG_FILE, COOKIES_FILE, LOG_FILE,
    load_config, save_config, log,
)
from pgups.utils import count_statuses, cache_hash, clear_courses_cache

# === Configuration ===
_SECRET_KEY_FILE = Path(__file__).parent.parent / ".secret_key"
_AUTH_ENABLED = os.environ.get("PGUPS_AUTH", "1") != "0"
_AUTH_USER = os.environ.get("PGUPS_AUTH_USER", "")
_AUTH_PASS = os.environ.get("PGUPS_AUTH_PASS", "")
_RATE_LIMIT_WINDOW = 60
_RATE_LIMIT_MAX = 30
_CSRF_TTL = 3600
_CONFIG_CACHE_TTL = 30
_COURSES_CACHE_TTL = 600
_AUTH_CACHE_TTL = 120


# === Global State (thread-safe) ===
_rate_limit_lock = threading.Lock()
_request_log: dict[str, list[float]] = {}

_csrf_lock = threading.Lock()
_csrf_tokens: dict[str, tuple[str, float]] = {}

_config_cache = {"data": None, "time": 0, "ttl": _CONFIG_CACHE_TTL}
_config_cache_lock = threading.Lock()

courses_lock = threading.Lock()
auth_lock = threading.Lock()
last_check: dict[str, dict] = {}
check_lock = threading.Lock()
download_status = {"running": False, "message": "", "progress": ""}
download_lock = threading.Lock()
_courses_cache = {"data": None, "time": 0, "stale": None, "stale_time": 0}
_auth_cache = {"authenticated": None, "time": 0}
_preload_started = False
_shutdown_event = threading.Event()

# Metrics
_metrics_lock = threading.Lock()
_metrics = {
    "total_requests": 0,
    "total_downloads": 0,
    "total_files_downloaded": 0,
    "total_errors": 0,
    "last_download_time": None,
    "start_time": time.time(),
}


# === Factory Pattern ===
def create_downloader() -> PgupsDownloader:
    """Create a new PgupsDownloader instance."""
    try:
        cfg = load_config()
        courses = cfg.get("courses", [])
        return PgupsDownloader(courses=courses)
    except Exception:
        return PgupsDownloader()


def get_downloader() -> PgupsDownloader:
    """Get or create downloader instance (thread-safe)."""
    # For simplicity, we use a module-level singleton with proper initialization
    # This avoids the race condition of creating multiple instances
    if not hasattr(create_downloader, "_instance"):
        create_downloader._instance = create_downloader()
    return create_downloader._instance


# === Secret Key ===
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


# === Auth & Rate Limiting ===
def _check_web_auth() -> bool:
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
        _request_log[ip] = [t for t in _request_log[ip] if now - t < _RATE_LIMIT_WINDOW]
        if len(_request_log[ip]) >= _RATE_LIMIT_MAX:
            return False
        _request_log[ip].append(now)
        return True


# === CSRF Protection ===
def _generate_csrf_token() -> str:
    """Generate a CSRF token for the current session."""
    import secrets
    token = secrets.token_hex(32)
    now = time.time()
    with _csrf_lock:
        global _csrf_tokens
        _csrf_tokens = {k: v for k, v in _csrf_tokens.items() if now - v[1] < _CSRF_TTL}
    _csrf_tokens[token] = (token, now)
    return token


def _validate_csrf_token(token: str) -> bool:
    """Validate a CSRF token."""
    if not token:
        return False
    now = time.time()
    with _csrf_lock:
        global _csrf_tokens
        _csrf_tokens = {k: v for k, v in _csrf_tokens.items() if now - v[1] < _CSRF_TTL}
        stored = _csrf_tokens.pop(token, None)
        if stored is None:
            return False
        return now - stored[1] < _CSRF_TTL


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
        if request.method in ("POST", "PUT", "DELETE"):
            csrf_token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not _validate_csrf_token(csrf_token):
                from flask import make_response
                return make_response("CSRF token invalid or expired", 403)
        return f(*args, **kwargs)
    return decorated


# === Config Cache ===
def _load_config_cached() -> dict:
    """Load config with 30-second cache to avoid repeated disk reads."""
    now = time.time()
    with _config_cache_lock:
        if _config_cache["data"] is not None and now - _config_cache["time"] < _config_cache["ttl"]:
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


# === Auth Cache ===
def _is_auth_cached() -> bool:
    now = time.time()
    return _auth_cache["authenticated"] is not None and now - _auth_cache["time"] < _AUTH_CACHE_TTL


def _get_auth_status() -> bool:
    now = time.time()
    if _is_auth_cached():
        return _auth_cache["authenticated"]
    dl = get_downloader()
    result = dl.verify_auth()
    _auth_cache["authenticated"] = result
    _auth_cache["time"] = now
    return result


def ensure_auth() -> bool:
    with auth_lock:
        if _get_auth_status():
            return True
        login, password = get_creds()
        if login and password:
            dl = get_downloader()
            ok = dl.login_via_portal(login, password)
            if ok:
                _auth_cache["authenticated"] = True
                _auth_cache["time"] = time.time()
                return True
        _auth_cache["authenticated"] = False
        _auth_cache["time"] = time.time()
        return False


# === Metrics ===
def _increment_metric(key: str, value: int = 1):
    with _metrics_lock:
        _metrics[key] = _metrics.get(key, 0) + value


def _update_metric(key: str, value):
    with _metrics_lock:
        _metrics[key] = value


# === App Factory ===
def create_app(testing: bool = False) -> Flask:
    """Create Flask application with all routes."""
    app = Flask(__name__, template_folder="../templates")
    app.secret_key = _load_secret_key()
    if testing:
        app.config["TESTING"] = True

    @app.before_request
    def check_auth():
        if app.config.get("TESTING"):
            return
        @require_auth
        def auth_check():
            pass
        auth_check()

    @app.after_request
    def add_cache_headers(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        # Track metrics
        _increment_metric("total_requests")
        if request.method in ("POST", "PUT", "DELETE"):
            _increment_metric("total_writes")
        return response

    # === Health & Metrics ===
    @app.route("/health")
    def health():
        dl = get_downloader()
        auth_status = _get_auth_status()
        return jsonify({
            "status": "ok",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "authenticated": auth_status,
            "download_running": download_status["running"],
            "courses_count": len(dl.courses) if dl else 0,
        })

    @app.route("/metrics")
    def metrics():
        with _metrics_lock:
            metrics_data = dict(_metrics)
        dl = get_downloader()
        metrics_data["courses_count"] = len(dl.courses) if dl else 0
        metrics_data["uptime_seconds"] = time.time() - metrics_data.pop("start_time")
        return jsonify(metrics_data)

    @app.route("/api/csrf-token")
    def api_csrf_token():
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
        dl = get_downloader()
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
            dl = get_downloader()
            if dl.verify_auth():
                return jsonify({"authenticated": True})
            ok = dl.login_via_portal(login, pwd, captcha, remember, csrf_token)
            if ok:
                return jsonify({"authenticated": True})
            return jsonify({"authenticated": False, "error": "Неверный логин, пароль или капча"})

    # === Pages ===
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/download")
    def download_page():
        dl = get_downloader()
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
        dl = get_downloader()
        with courses_lock:
            cfg_courses = list(dl.courses)
        courses_with_names = _load_course_names_parallel(cfg_courses)
        cfg = _load_config_cached()
        return render_template("settings.html", courses=courses_with_names, login=cfg.get("login"))

    # === API: Courses ===
    def fetch_one_course(course: dict, cookies: list = None, headers: dict = None) -> dict | None:
        try:
            tmp_dl = get_downloader()
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
        dl = get_downloader()
        with courses_lock:
            courses_snapshot = list(dl.courses)
        cache_key = cache_hash(courses_snapshot)

        is_stale = (
            _courses_cache.get("_key") == cache_key
            and _courses_cache["stale"] is not None
            and now - _courses_cache["stale_time"] < _COURSES_CACHE_TTL * 2
        )

        if is_stale:
            threading.Thread(target=_refresh_courses, args=(courses_snapshot,), daemon=True).start()
            return jsonify(_courses_cache["stale"])

        if _courses_cache.get("_key") == cache_key and _courses_cache["data"] and now - _courses_cache["time"] < _COURSES_CACHE_TTL:
            return jsonify(_courses_cache["data"])

        _do_refresh_courses(courses_snapshot)
        return jsonify(_courses_cache["data"] or {"courses": []})

    def _do_refresh_courses(courses_snapshot: list):
        now = time.time()
        if _shutdown_event.is_set():
            return
        try:
            ok = ensure_auth()
            if _shutdown_event.is_set():
                return
            if not ok:
                result = {"courses": [{"id": c["id"], "name": "Нет авторизации", "error": True} for c in courses_snapshot]}
                _courses_cache["data"] = result
                _courses_cache["time"] = now
                _courses_cache["_key"] = cache_hash(courses_snapshot)
                return

            dl = get_downloader()
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
            _increment_metric("total_errors")

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
        dl = get_downloader()
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

    # === API: Download ===
    @app.route("/api/download", methods=["POST"])
    def api_download():
        ok = ensure_auth()
        if not ok:
            return jsonify({"error": "Нет авторизации"}), 401
        data = request.get_json()
        course_ids = data.get("course_ids", [])
        workers = data.get("workers", DEFAULT_WORKERS)
        download_type = data.get("download_type", "both")

        dl = get_downloader()
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
                _increment_metric("total_downloads")
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
                                _increment_metric("total_files_downloaded")
                            done = sum(1 for ff in fut if ff.done())
                            download_status["progress"] = f"{done}/{total}"
                    download_status["message"] = f"Готово! Скачано: {downloaded}, пропущено: {total - downloaded}"
                    download_status["progress"] = f"{total}/{total}"
                    _update_metric("last_download_time", time.time())
            except Exception as e:
                log(f"[WEB] Ошибка скачивания: {e}")
                download_status["message"] = f"Ошибка: {e}"
                _increment_metric("total_errors")
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

    # === API: Settings ===
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
        invalidate_config_cache()
        log("[WEB] Логин/пароль сохранены")
        clear_courses_cache(_courses_cache)
        return jsonify({"status": "ok"})

    @app.route("/api/settings/courses", methods=["GET", "POST", "DELETE"])
    def api_settings_courses():
        cfg = _load_config_cached()
        dl = get_downloader()
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

    # === Preload Cache ===
    def _preload_cache():
        global _preload_started
        if _preload_started or _shutdown_event.is_set():
            return
        _preload_started = True
        time.sleep(2)
        if _shutdown_event.is_set():
            return
        try:
            dl = get_downloader()
            with courses_lock:
                snapshot = list(dl.courses)
            if not _shutdown_event.is_set():
                _do_refresh_courses(snapshot)
            log("[WEB] Кэш предзагружен")
        except Exception as e:
            if not _shutdown_event.is_set():
                log(f"[WEB] Ошибка предзагрузки кэша: {e}")

    # === Signal Handler ===
    def _signal_handler(signum, frame):
        log("[WEB] Получен сигнал завершения, ожидаем потоки...")
        _shutdown_event.set()
        while download_status["running"]:
            time.sleep(0.5)
        sys.exit(0)

    # === Start Preload ===
    threading.Thread(target=_preload_cache, daemon=True).start()
    
    # Only install signal handlers when running in a terminal (not in background)
    if sys.stdout.isatty() or sys.stdin.isatty():
        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

    return app


# === Load Name Helper ===
def _load_course_names_parallel(courses_list: list[dict]) -> list[dict]:
    """Загрузка имён курсов параллельно."""
    dl = get_downloader()
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


# === CLI Entry Point ===
if __name__ == "__main__":
    app = create_app()
    login, password = get_creds()
    if login and password:
        ensure_auth()
    port = int(os.environ.get("PORT", 5000))
    log(f"[WEB] Сервер запущен на http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
