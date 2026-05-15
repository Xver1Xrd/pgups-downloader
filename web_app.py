#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import threading
from pathlib import Path
from flask import Flask, jsonify, render_template, request, session as flask_session

sys.path.insert(0, str(Path(__file__).parent))
from pgups_downloader import (
    PgupsDownloader, BASE_URL, DOWNLOAD_BASE, DEFAULT_WORKERS,
    CONFIG_FILE, COOKIES_FILE, LOG_FILE,
    load_config, save_config, log,
)

app = Flask(__name__)
app.secret_key = os.urandom(32)

dl = PgupsDownloader()
auth_lock = threading.Lock()
last_check: dict[str, dict] = {}
check_lock = threading.Lock()
download_status = {"running": False, "message": "", "progress": ""}
download_lock = threading.Lock()


def get_creds() -> tuple[str, str]:
    cfg = load_config()
    return cfg.get("login", ""), cfg.get("password", "")


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
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    captcha = data.get("captcha", "").strip()
    remember = data.get("remember", False)

    login, pwd = email or get_creds()[0], password or get_creds()[1]
    with auth_lock:
        if dl.verify_auth():
            return jsonify({"authenticated": True})
        ok = dl.login_via_portal(login, pwd, captcha, remember)
        if ok:
            return jsonify({"authenticated": True})
        return jsonify({"authenticated": False, "error": "Неверный логин, пароль или капча"})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/download")
def download_page():
    cfg_courses = load_config().get("courses", dl.courses)
    courses_with_names = []
    for c in cfg_courses:
        try:
            name = dl.get_course_name(c["url"])
        except Exception:
            name = f"Курс {c['id']}"
        courses_with_names.append({"id": c["id"], "url": c["url"], "name": name})
    return render_template("download.html", courses=courses_with_names, default_workers=DEFAULT_WORKERS)


@app.route("/course/<course_id>")
def course_page(course_id):
    return render_template("course.html", course_id=course_id)


@app.route("/add-course")
def add_course_page():
    return render_template("add_course.html")


@app.route("/settings")
def settings_page():
    cfg_courses = load_config().get("courses", dl.courses)
    courses_with_names = []
    for c in cfg_courses:
        try:
            name = dl.get_course_name(c["url"])
        except Exception:
            name = f"Курс {c['id']}"
        courses_with_names.append({"id": c["id"], "url": c["url"], "name": name})
    return render_template("settings.html", courses=courses_with_names, login=load_config().get("login"))


_courses_cache = {"data": None, "time": 0}
CACHE_TTL = 300

def fetch_one_course(course: dict, cookies: list = None, headers: dict = None) -> dict | None:
    try:
        tmp = PgupsDownloader()
        if cookies:
            for c in cookies:
                tmp.session.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
        if headers:
            tmp.session.headers.update(headers)
        rows, name = tmp.check_course(course["url"])
    except Exception as e:
        return {"id": course["id"], "name": f"Ошибка: {e}", "error": True}
    passed = failed = submitted = locked = pending = 0
    items = []
    for r in rows:
        s = r["status"]
        if s.startswith("+"):
            passed += 1
        elif s.startswith("-"):
            failed += 1
        elif s.startswith("~"):
            submitted += 1
        elif s.startswith("#"):
            locked += 1
        else:
            pending += 1
        items.append(r)
    return {
        "id": course["id"],
        "name": name,
        "url": course["url"],
        "passed": passed,
        "failed": failed,
        "submitted": submitted,
        "locked": locked,
        "pending": pending,
        "items": items,
    }

@app.route("/api/courses")
def api_courses():
    now = time.time()
    if _courses_cache["data"] and now - _courses_cache["time"] < CACHE_TTL:
        return jsonify(_courses_cache["data"])

    ok = ensure_auth()
    if not ok:
        return jsonify({"courses": [{"id": c["id"], "name": "Нет авторизации", "error": True} for c in dl.courses]})

    from concurrent.futures import ThreadPoolExecutor, as_completed
    cookies = list(dl.session.cookies)
    headers = dict(dl.session.headers)
    results = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        fut = {pool.submit(fetch_one_course, c, cookies, headers): c for c in dl.courses}
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
            last_check[key] = {i["name"]: i["status"] for i in r["items"]}
            if key in prev:
                old = prev[key]
                for item in r["items"]:
                    if item["name"] in old and old[item["name"]] != item["status"]:
                        item["changed"] = True
                        item["prev_status"] = old[item["name"]]

    data = {"courses": results}
    _courses_cache["data"] = data
    _courses_cache["time"] = now
    return jsonify(data)


@app.route("/api/course/<course_id>")
def api_course(course_id):
    ok = ensure_auth()
    if not ok:
        return jsonify({"error": "Нет авторизации"}), 401
    course = next((c for c in dl.courses if c["id"] == course_id), None)
    if not course:
        return jsonify({"error": "Курс не найден"}), 404
    try:
        rows, name = dl.check_course(course["url"])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    passed = failed = submitted = locked = pending = 0
    for r in rows:
        s = r["status"]
        if s.startswith("+"):
            passed += 1
        elif s.startswith("-"):
            failed += 1
        elif s.startswith("~"):
            submitted += 1
        elif s.startswith("#"):
            locked += 1
        else:
            pending += 1
    return jsonify({
        "id": course_id,
        "name": name,
        "passed": passed,
        "failed": failed,
        "submitted": submitted,
        "locked": locked,
        "pending": pending,
        "items": rows,
    })


@app.route("/api/download", methods=["POST"])
def api_download():
    ok = ensure_auth()
    if not ok:
        return jsonify({"error": "Нет авторизации"}), 401
    data = request.get_json()
    course_ids = data.get("course_ids", [])
    workers = data.get("workers", DEFAULT_WORKERS)

    if course_ids:
        courses = [c for c in dl.courses if c["id"] in course_ids]
    else:
        courses = dl.courses

    if not courses:
        return jsonify({"error": "Курсы не найдены"}), 404

    with download_lock:
        if download_status["running"]:
            return jsonify({"error": "Скачивание уже выполняется"}), 409
        download_status["running"] = True
        download_status["message"] = "Запуск..."
        download_status["progress"] = ""

    def run_dl():
        original = dl.courses
        dl.courses = courses
        dl.workers = workers
        try:
            log(f"\n[WEB] Скачивание {len(courses)} курсов ({workers} потоков)")
            download_status["message"] = "Сбор заданий..."
            tasks = dl.collect_tasks()
            if not tasks:
                download_status["message"] = "Нет файлов для скачивания"
                download_status["progress"] = "0/0"
            else:
                download_status["message"] = f"Скачивание {len(tasks)} файлов..."
                downloaded = 0
                from concurrent.futures import ThreadPoolExecutor, as_completed
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    fut = {pool.submit(dl.download_file, url, name, folder): name
                           for url, name, folder in tasks}
                    for f in as_completed(fut):
                        if f.result():
                            downloaded += 1
                        done = sum(1 for ff in fut if ff.done())
                        download_status["progress"] = f"{done}/{len(tasks)}"
                download_status["message"] = f"Готово! Скачано: {downloaded}, пропущено: {len(tasks) - downloaded}"
                download_status["progress"] = f"{len(tasks)}/{len(tasks)}"
            dl.courses = original
        except Exception as e:
            download_status["message"] = f"Ошибка: {e}"
            dl.courses = original
        finally:
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
    cfg = load_config()
    if login:
        cfg["login"] = login
    if password:
        cfg["password"] = password
    save_config(cfg)
    log("[WEB] Логин/пароль сохранены")
    return jsonify({"status": "ok"})


@app.route("/api/settings/courses", methods=["GET", "POST", "DELETE"])
def api_settings_courses():
    cfg = load_config()
    courses = cfg.get("courses", dl.courses)

    if request.method == "GET":
        result = []
        for c in courses:
            try:
                name = dl.get_course_name(c["url"])
            except Exception:
                name = f"Курс {c['id']}"
            result.append({"id": c["id"], "url": c["url"], "name": name})
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
        dl.courses = courses
        log(f"[WEB] Курс {course_id} добавлен")
        return jsonify({"status": "ok", "id": course_id})

    if request.method == "DELETE":
        data = request.get_json()
        course_id = data.get("id")
        courses = [c for c in courses if c["id"] != course_id]
        cfg["courses"] = courses
        save_config(cfg)
        dl.courses = courses
        log(f"[WEB] Курс {course_id} удалён")
        return jsonify({"status": "ok"})


@app.route("/api/settings/logs", methods=["DELETE"])
def api_clear_logs():
    if LOG_FILE.exists():
        LOG_FILE.unlink()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    login, password = get_creds()
    if login and password:
        ensure_auth()
    port = int(os.environ.get("PORT", 5000))
    log(f"[WEB] Сервер запущен на http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
