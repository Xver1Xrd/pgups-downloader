#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import requests
from pathlib import Path
from urllib.parse import urljoin, unquote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from captcha_solver import auto_solve_captcha, solve_one_captcha, get_csrf_and_captcha

BASE_URL = "https://sdo.pgups.ru"
MY_BASE_URL = "https://my.pgups.ru"
CONFIG_FILE = Path(__file__).parent / "config.json"
COOKIES_FILE = Path(__file__).parent / "cookies.txt"
DOWNLOAD_BASE = Path.home() / "Downloads" / "pgups"
LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "pgups.log"
DEFAULT_WORKERS = 3

log_lock = Lock()


def log(msg: str):
    with log_lock:
        print(msg)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")


def sanitize(name: str, strip_задание: bool = False) -> str:
    name = name.strip()
    if strip_задание:
        name = re.sub(r"\s*Задание\s*$", "", name, flags=re.IGNORECASE)
    name = re.sub(r'[\\/:*?"<>|]', " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    name = name.rstrip(". ")
    return name or "untitled"


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(cfg: dict):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


class PgupsDownloader:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })
        self.config = load_config()
        self.courses = self.config.get("courses", [
            {"id": "4388", "url": f"{BASE_URL}/course/view.php?id=4388"},
            {"id": "7036", "url": f"{BASE_URL}/course/view.php?id=7036"},
            {"id": "7031", "url": f"{BASE_URL}/course/view.php?id=7031"},
            {"id": "6920", "url": f"{BASE_URL}/course/view.php?id=6920"},
            {"id": "6467", "url": f"{BASE_URL}/course/view.php?id=6467"},
            {"id": "6964", "url": f"{BASE_URL}/course/view.php?id=6964"},
            {"id": "7039", "url": f"{BASE_URL}/course/view.php?id=7039"},
            {"id": "7009", "url": f"{BASE_URL}/course/view.php?id=7009"},
        ])
        self.workers = DEFAULT_WORKERS

    def load_cookies(self) -> bool:
        if not COOKIES_FILE.exists():
            return False
        count = 0
        moodle_found = False
        with open(COOKIES_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    domain, _, path, secure, expires, name, value = parts[:7]
                    self.session.cookies.set(name, value, domain=domain, path=path)
                    count += 1
                    if "sdo.pgups.ru" in domain and name == "MoodleSession":
                        moodle_found = True
        log(f"[*] Загружено {count} cookies")
        return moodle_found

    def verify_auth(self) -> bool:
        try:
            r = self.session.get(f"{BASE_URL}/my/", timeout=10, allow_redirects=True)
            if "login" in r.url.lower():
                return False
            if "Гость" in r.text or "гостевой доступ" in r.text.lower():
                return False
            return True
        except Exception:
            return False

    def login(self, username: str, password: str) -> bool:
        log("[*] Попытка входа…")
        r = self.session.get(f"{BASE_URL}/login/index.php", timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        if not form:
            log("[!] Форма входа не найдена")
            return False

        action = form.get("action", "")
        post_url = urljoin(BASE_URL, action)
        data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                data[name] = inp.get("value", "")
        data["username"] = username
        data["password"] = password

        r = self.session.post(post_url, data=data, allow_redirects=True)

        if "2fa" in r.url.lower() or "otp" in r.url.lower() or "code" in r.url.lower():
            code = input("[?] Введите код 2FA из почты: ").strip()
            soup = BeautifulSoup(r.text, "html.parser")
            form = soup.find("form")
            if form:
                action = form.get("action", "")
                post_url = urljoin(BASE_URL, action)
                data = {}
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if name:
                        data[name] = inp.get("value", "")
                data["code"] = code
                r = self.session.post(post_url, data=data, allow_redirects=True)

        ok = self.verify_auth()
        log("[✓] Вход выполнен" if ok else "[✗] Ошибка входа")
        if ok:
            self._save_session_cookies()
        return ok

    def _save_session_cookies(self):
        now_ts = int(time.time()) + 86400 * 7
        lines = ["# Netscape HTTP Cookie File"]
        seen = set()
        for cookie in self.session.cookies:
            if not cookie.domain:
                continue
            key = (cookie.domain, cookie.name, cookie.path)
            if key in seen:
                continue
            seen.add(key)
            domain = cookie.domain
            flag = "TRUE" if domain.startswith(".") else "FALSE"
            path = cookie.path or "/"
            secure = "TRUE" if cookie.secure else "FALSE"
            expires = str(int(cookie.expires)) if cookie.expires else str(now_ts)
            lines.append(f"{domain}\t{flag}\t{path}\t{secure}\t{expires}\t{cookie.name}\t{cookie.value}")
        with open(COOKIES_FILE, "w") as f:
            f.write("\n".join(lines) + "\n")
        log(f"[*] Сохранено {len(seen)} cookies")

    def get_captcha(self) -> dict | None:
        try:
            r = self.session.get(f"{MY_BASE_URL}/login", timeout=15)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            form = soup.find("form")
            if not form:
                return None

            token_input = form.find("input", {"name": "_token"})
            if not token_input:
                return None
            csrf_token = token_input.get("value", "")

            captcha_img = soup.find("img", alt=lambda a: a and "captcha" in a.lower()) if soup else None
            captcha_url = urljoin(MY_BASE_URL, captcha_img.get("src", "")) if captcha_img else ""

            captcha_data = b""
            if captcha_url:
                r_img = self.session.get(captcha_url, timeout=15)
                if r_img.status_code == 200:
                    captcha_data = r_img.content

            return {
                "csrf_token": csrf_token,
                "captcha_url": captcha_url,
                "captcha_data": captcha_data,
                "session_cookies": list(self.session.cookies),
            }
        except Exception as e:
            log(f"[!] get_captcha error: {e}")
            return None

    def login_via_portal(self, email: str, password: str, captcha: str = "", remember: bool = True) -> bool:
        old_cookies = list(self.session.cookies)

        for attempt in range(8 if not captcha else 1):
            try:
                if not captcha:
                    log(f"[*] Авто-капча: попытка {attempt + 1}/8…")
                    token, captcha_img = get_csrf_and_captcha(self.session)
                    if not token or not captcha_img:
                        continue
                    csrf_token = token
                    captcha_text = solve_one_captcha(captcha_img)
                    if not captcha_text:
                        continue
                else:
                    r = self.session.get(f"{MY_BASE_URL}/login", timeout=15)
                    soup = BeautifulSoup(r.text, "html.parser")
                    form = soup.find("form")
                    if not form:
                        log("[!] Форма входа на my.pgups.ru не найдена")
                        return False
                    token_input = form.find("input", {"name": "_token"})
                    if not token_input:
                        log("[!] CSRF токен не найден")
                        return False
                    csrf_token = token_input.get("value", "")
                    captcha_text = captcha

                data = {
                    "_token": csrf_token,
                    "email": email,
                    "password": password,
                    "captcha": captcha_text,
                    "remember": "on" if remember else "",
                }

                log(f"[*] Отправка формы входа на my.pgups.ru (капча: {captcha_text})…")
                r2 = self.session.post(
                    f"{MY_BASE_URL}/login",
                    data=data,
                    allow_redirects=True,
                    timeout=30,
                )

                is_success = (
                    "/captcha" not in r2.url.lower()
                    and "/login" not in r2.url.lower()
                )
                if is_success:
                    log(f"[*] Редирект на: {r2.url}")
                    self._save_session_cookies()
                    log("[*] Запуск SSO через my.pgups.ru/auth/sdo…")
                    self.session.get(f"{MY_BASE_URL}/auth/sdo", timeout=15, allow_redirects=True)
                    self._save_session_cookies()
                    if self.verify_auth():
                        log("[✓] Вход через портал выполнен")
                        return True

                log(f"[✗] Попытка {attempt + 1} не удалась")
                if not captcha:
                    captcha = ""
            except Exception as e:
                log(f"[!] login_via_portal error: {e}")
                if not captcha:
                    captcha = ""

        if not captcha:
            log("[!] Авто-капча не удалась после 8 попыток")
            for c in old_cookies:
                self.session.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
        return False

    def get_course_name(self, course_url: str) -> str:
        fallback = f"Курс {course_url.split('=')[-1]}"
        try:
            r = self.session.get(course_url, timeout=10)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")

            body_text = soup.get_text()
            if "Этот курс скрыт" in body_text or "гостевой доступ" in body_text.lower():
                return fallback

            h1 = soup.find("h1")
            if h1:
                text = h1.get_text(strip=True)
                if text:
                    return sanitize(text)

            nav = soup.find("nav", class_=lambda c: c and "breadcrumb" in c.lower())
            if nav:
                items = nav.find_all("li")
                if len(items) >= 2:
                    last = items[-1].get_text(strip=True)
                    if last and "В начало" not in last:
                        return sanitize(last)

            for tag in soup.find_all(["h2", "h3"]):
                text = tag.get_text(strip=True)
                if text and len(text) > 3 and "Блоки" not in text:
                    return sanitize(text)

            title = soup.find("title")
            if title:
                text = title.get_text(strip=True)
                if text:
                    name = text.split("|")[0].replace("Курс:", "").strip()
                    if name.lower() not in ("уведомление", "notification", "site announcements"):
                        return sanitize(name)

            return fallback
        except Exception as e:
            log(f"[!] get_course_name error for {course_url}: {e}")
            return fallback

    def get_assignments_from_course(self, course_url: str) -> list[dict]:
        r = self.session.get(course_url, timeout=10)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        assignments = []
        seen = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "/mod/assign/view.php?id=" in href:
                assign_id = href.split("=")[-1].split("&")[0]
                if assign_id in seen:
                    continue
                seen.add(assign_id)
                name = link.get_text(strip=True)
                if not name:
                    name = f"lab_{assign_id}"
                assignments.append({
                    "id": assign_id,
                    "name": name,
                    "url": href if href.startswith("http") else urljoin(BASE_URL, href),
                })
        return assignments

    def get_submission_files(self, assign_url: str) -> list[dict]:
        r = self.session.get(assign_url, timeout=10)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        files = []
        seen_urls = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "pluginfile.php" in href and "submission_files" in href:
                full_url = href if href.startswith("http") else urljoin(BASE_URL, href)
                if full_url in seen_urls:
                    continue
                seen_urls.add(full_url)
                filename = unquote(full_url.split("/")[-1].split("?")[0])
                files.append({"url": full_url, "filename": filename})
        return files

    def check_remote_size(self, url: str) -> int | None:
        try:
            r = self.session.head(url, timeout=10, allow_redirects=True)
            if r.status_code == 200:
                ct = r.headers.get("Content-Length")
                if ct:
                    return int(ct)
        except Exception:
            pass
        return None

    def download_file(self, url: str, filename: str, folder: Path) -> bool:
        folder.mkdir(parents=True, exist_ok=True)
        filepath = folder / filename

        remote_size = self.check_remote_size(url)

        if remote_size is not None and filepath.exists():
            if filepath.stat().st_size == remote_size:
                return False
            log(f"  ↻ {filename} (обновлён на сервере)")

        log(f"  ↓ {filename}")
        try:
            r = self.session.get(url, stream=True, timeout=120)
            r.raise_for_status()
            path = filepath
            tmp = folder / f".{filename}.part"
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            new_size = tmp.stat().st_size

            for existing in folder.iterdir():
                if existing.name.endswith(".part"):
                    continue
                if existing.is_file() and existing.stat().st_size == new_size and existing.name != path.name:
                    tmp.unlink()
                    log(f"     уже есть: {existing.name}")
                    return False

            updated = path.exists()
            if updated:
                path.unlink()
            tmp.rename(path)
            icon = "↻" if updated else "✓"
            log(f"    {icon} {new_size/1024:.1f} KB")
            return True
        except Exception as e:
            log(f"    ✗ ошибка: {e}")
            return False

    def _check_submission_and_deadline(self, assign_url: str) -> tuple[bool, str | None]:
        try:
            r = self.session.get(assign_url, timeout=10)
            if r.status_code != 200:
                return False, None
            soup = BeautifulSoup(r.text, "html.parser")
            has_files = False
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if "pluginfile.php" in href and "submission_files" in href:
                    has_files = True
                    break
            dl = None
            for tag in soup.find_all(["div", "p", "dd", "dt", "td", "strong"]):
                txt = tag.get_text(strip=True)
                if "Срок сдачи" in txt:
                    after = txt.split("Срок сдачи")[-1].strip(": \t\n")
                    m = re.match(r"\s*([^<]+?\d{2}:\d{2})", after)
                    if m:
                        dl = m.group(1).strip()
                    else:
                        dl = after.split(".")[0].strip()[:50]
                    break
            return has_files, dl
        except Exception:
            return False, None

    def get_deadline(self, url: str) -> str | None:
        try:
            r = self.session.get(url, timeout=6)
            if r.status_code != 200:
                return None
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(["div", "p", "dd", "dt", "td", "strong"]):
                txt = tag.get_text(strip=True)
                if "Срок сдачи" in txt:
                    after = txt.split("Срок сдачи")[-1].strip(": \t\n")
                    m = re.match(r"\s*([^<]+?\d{2}:\d{2})", after)
                    if m:
                        return m.group(1).strip()
                    return after.split(".")[0].strip()[:50]
            return None
        except Exception:
            return None

    def check_course(self, course_url: str) -> list[dict]:
        course_id = course_url.split("=")[-1]
        course_name = self.get_course_name(course_url)

        locked_ids = set()
        r2 = self.session.get(course_url, timeout=10)
        soup2 = BeautifulSoup(r2.text, "html.parser")
        for act in soup2.find_all("li", class_="activity"):
            info = act.find("div", class_="availabilityinfo")
            if info and "Недоступно" in info.get_text():
                cm_id = act.get("data-id")
                iname = act.find("span", class_="instancename")
                locked_ids.add((cm_id, iname.get_text(strip=True) if iname else ""))

        r = self.session.get(
            f"{BASE_URL}/grade/report/user/index.php?id={course_id}", timeout=10
        )
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        table = soup.find("table", class_="generaltable")
        if not table:
            return [], course_name

        def clean_name(raw: str) -> str:
            s = re.sub(r"\s*Действия.*", "", raw).strip()
            s = re.sub(r"^(Тест|Задание)\s+", "", s).strip()
            s = re.sub(r"\s+", " ", s).strip()
            return s

        def is_locked(raw_name: str, cm_id: str | None = None) -> bool:
            for lid, lname in locked_ids:
                if cm_id and lid == cm_id:
                    return True
                if lname and (lname in raw_name or raw_name[:20] in lname):
                    return True
            return False

        rows_data = []
        check_submission = []

        for row in table.find_all("tr"):
            cells = row.find_all(["td", "th"])
            if len(cells) < 3:
                continue
            name_raw = cells[0].get_text(" ", strip=True)
            if not name_raw or "Элемент оценивания" in name_raw or "Б1." in name_raw:
                continue

            type_prefix = name_raw.split()[0] if name_raw.split() else ""
            if type_prefix not in ("Тест", "Задание"):
                continue

            name = clean_name(name_raw)
            if "итогов" in name.lower():
                continue

            grade_raw = cells[2].get_text(" ", strip=True)
            grade_raw = re.sub(r"\s*Действия.*", "", grade_raw).strip()

            letter = ""
            score = ""
            m_grade = re.match(r"([А-Яа-я]+)\s*\(([\d,]+)\)", grade_raw)
            if m_grade:
                letter = m_grade.group(1)
                score = m_grade.group(2)

            cm_id = None
            assign_url = None
            for a in cells[0].find_all("a", href=True):
                m = re.search(r"id=(\d+)", a["href"])
                if m:
                    cm_id = m.group(1)
                    assign_url = a["href"]
                    break

            locked = is_locked(name_raw, cm_id)

            if grade_raw and grade_raw not in ("-", "( Пусто )"):
                if letter in ("Отл", "Хор", "Удовл"):
                    status = f"+ {letter} ({score})"
                elif letter == "Неуд":
                    status = f"- Неуд ({score})"
                else:
                    status = f"? {grade_raw}"
                rows_data.append({"name": name, "status": status})
            elif locked:
                rows_data.append({"name": name, "status": "# заблокирован"})
            elif type_prefix == "Задание" and assign_url:
                check_submission.append({
                    "name": name,
                    "url": assign_url,
                })
            else:
                rows_data.append({"name": name, "status": ". не пройдено"})

        if check_submission:
            with ThreadPoolExecutor(max_workers=5) as pool:
                fut = {
                    pool.submit(self._check_submission_and_deadline, item["url"]): item["name"]
                    for item in check_submission
                }
                results = {}
                for f in as_completed(fut):
                    name = fut[f]
                    has_sub, dl = f.result()
                    results[name] = (has_sub, dl)
            for item in check_submission:
                has_sub, dl = results.get(item["name"], (False, None))
                if has_sub:
                    rows_data.append({"name": item["name"], "status": "~ сдано / не проверено"})
                else:
                    rows_data.append({"name": item["name"], "status": ". не сдано"})
                if dl:
                    rows_data[-1]["deadline"] = dl

        return rows_data, course_name

    def check_all(self):
        log("\n" + "=" * 55)
        log("PGUPS — Проверка успеваемости")
        log("=" * 55)

        for course in self.courses:
            results, course_name = self.check_course(course["url"])
            if not results:
                continue
            log(f"\n── {course_name} ──")
            passed = failed = submitted = locked = pending = 0
            for r in results:
                if r["status"].startswith("+"):
                    passed += 1
                elif r["status"].startswith("-"):
                    failed += 1
                elif r["status"].startswith("~"):
                    submitted += 1
                elif r["status"].startswith("#"):
                    locked += 1
                else:
                    pending += 1
                log(f"  {r['status']}  {r['name']}")
            log(f"\n  Итого: ✅ {passed} | ❌ {failed} | 📤 {submitted} | 🔒 {locked} | ⏳ {pending}")

    def monitor_course(self, course_url: str, interval: int = 30):
        course_id = course_url.split("=")[-1]
        course_name = self.get_course_name(course_url)

        def fmt(results: list) -> dict[str, str]:
            return {r["name"]: r["status"] for r in results}

        prev: dict[str, str] = {}
        first = True

        while True:
            results, _ = self.check_course(course_url)
            curr = fmt(results)
            timestamp = time.strftime("%H:%M:%S")

            if first:
                os.system("clear" if os.name == "posix" else "cls")
                log(f"\n📡 Мониторинг: {course_name} (id={course_id})")
                log(f"   Интервал: {interval}с | Выход: Ctrl+C\n")
                for r in results:
                    log(f"  {r['status']}  {r['name']}")
                prev = curr
                first = False
            elif curr != prev:
                os.system("clear" if os.name == "posix" else "cls")
                log(f"\n📡 Мониторинг: {course_name} (id={course_id})")
                log(f"   Интервал: {interval}с | Выход: Ctrl+C\n")
                for r in results:
                    old = prev.get(r["name"])
                    if old and old != r["status"]:
                        log(f"  {r['status']}  {r['name']}  ← {old}")
                    else:
                        log(f"  {r['status']}  {r['name']}")
                prev = curr
            else:
                log(f"[{timestamp}] Нет изменений")

            time.sleep(interval)

    def watch(self, course_url: str | None = None, interval: int = 30):
        if not self.ensure_auth("", ""):
            return
        if course_url:
            try:
                self.monitor_course(course_url, interval)
            except KeyboardInterrupt:
                log("\n[*] Мониторинг остановлен")
        else:
            log("[!] Укажи ID курса: --course ID")

    def ensure_auth(self, username: str = "", password: str = "") -> bool:
        if self.load_cookies() and self.verify_auth():
            return True

        log("[*] Сессия истекла, пробую восстановить…")

        if not username:
            username = self.config.get("login", "")
            password = self.config.get("password", "")

        if username and password:
            if self.login(username, password):
                return True
            log("[*] Пробую вход через портал с авто-капчей…")
            return self.login_via_portal(username, password)

        log("[!] Нужна авторизация. Укажи --login / --pass или сохрани в config.json")
        return False

    def collect_tasks(self) -> list[tuple]:
        tasks = []
        for course in self.courses:
            course_name = self.get_course_name(course["url"])
            course_folder = DOWNLOAD_BASE / course_name
            course_count = 0
            course_folder.mkdir(parents=True, exist_ok=True)
            log(f"\n── {course_name} ──")

            assignments = self.get_assignments_from_course(course["url"])
            if not assignments:
                log("  → нет заданий")
                continue

            for assign in assignments:
                assign_name = sanitize(assign["name"], strip_задание=True)
                assign_folder = course_folder / assign_name if assign_name else course_folder

                files = self.get_submission_files(assign["url"])
                if not files:
                    continue
                log(f"  • {assign_name} ({len(files)})")

                course_count += len(files)
                for f in files:
                    tasks.append((f["url"], f["filename"], assign_folder))

            if course_count:
                log(f"  всего файлов: {course_count}")
        return tasks

    def run(self, username: str = "", password: str = "", save_login: bool = False, workers: int = DEFAULT_WORKERS):
        log("\n" + "=" * 55)
        log("PGUPS Downloader")
        log("=" * 55)

        self.workers = workers

        if save_login and username and password:
            self.config["login"] = username
            self.config["password"] = password
            self.config["courses"] = self.courses
            save_config(self.config)
            log("[*] Логин/пароль сохранены в config.json")

        if not self.ensure_auth(username, password):
            return

        tasks = self.collect_tasks()
        if not tasks:
            log("\nНет файлов для скачивания.")
            return

        log(f"\n── Скачивание ({len(tasks)} файлов, {self.workers} потоков) ──")

        downloaded = 0
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            fut = {pool.submit(self.download_file, url, name, folder): name
                   for url, name, folder in tasks}
            for f in as_completed(fut):
                if f.result():
                    downloaded += 1

        log(f"\n{'=' * 55}")
        skipped = len(tasks) - downloaded
        log(f"Готово! Скачано: {downloaded}, пропущено: {skipped}")
        log(f"Папка: {DOWNLOAD_BASE}")
        log(f"{'=' * 55}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Скачиватор лаб PGUPS")
    parser.add_argument("--login", help="Логин")
    parser.add_argument("--pass", dest="password", help="Пароль")
    parser.add_argument("--save-login", action="store_true",
                        help="Сохранить логин/пароль в config.json для авто-входа")
    parser.add_argument("--workers", type=int, default=None,
                        help=f"Количество потоков (по умолч. {DEFAULT_WORKERS})")
    parser.add_argument("--check", action="store_true",
                        help="Проверить успеваемость по всем курсам")
    parser.add_argument("--status", action="store_true", dest="check",
                        help="То же, что --check")
    parser.add_argument("-c", "--course", type=str,
                        help="ID курса для --check (например 6964)")
    parser.add_argument("-m", "--monitor", action="store_true",
                        help="Режим мониторинга (автообновление каждые N сек)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Интервал обновления в секундах (по умолч. 30)")
    parser.add_argument("--web", action="store_true",
                        help="Запустить веб-интерфейс")
    parser.add_argument("--port", type=int, default=5000,
                        help="Порт для веб-интерфейса (по умолч. 5000)")
    parser.add_argument("--login-portal", action="store_true",
                        help="Вход через my.pgups.ru (с капчей)")
    parser.add_argument("--captcha", type=str, default="",
                        help="Код капчи для входа через портал")
    args = parser.parse_args()

    dl = PgupsDownloader()

    if args.login_portal:
        login = args.login or load_config().get("login", "")
        password = args.password or load_config().get("password", "")
        if not args.captcha:
            args.captcha = input("[?] Введите код с картинки капчи (my.pgups.ru): ").strip()
        if login and password and args.captcha:
            ok = dl.login_via_portal(login, password, args.captcha)
            log("[✓] Вход выполнен" if ok else "[✗] Ошибка входа")
        return

    if args.web:
        from web_app import app
        app.run(host="0.0.0.0", port=args.port, debug=False)
        return

    if args.monitor:
        url = None
        if args.course:
            url = f"{BASE_URL}/course/view.php?id={args.course}"
        dl.watch(course_url=url, interval=args.interval)
        return

    if args.check:
        if not dl.ensure_auth(args.login or "", args.password or ""):
            return
        if args.course:
            url = f"{BASE_URL}/course/view.php?id={args.course}"
            results, name = dl.check_course(url)
            log(f"\n── {name} ──")
            for r in results:
                log(f"  {r['status']}  {r['name']}")
        else:
            dl.check_all()
        return

    dl.run(
        username=args.login or "",
        password=args.password or "",
        save_login=args.save_login,
        workers=args.workers or DEFAULT_WORKERS,
    )


if __name__ == "__main__":
    main()
