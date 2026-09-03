#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import subprocess
import hashlib
from pathlib import Path
from urllib.parse import urljoin, unquote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import requests
from captcha_solver import solve_one_captcha, get_csrf_and_captcha

BASE_URL = "https://sdo.pgups.ru"
MY_BASE_URL = "https://my.pgups.ru"
CONFIG_FILE = Path(__file__).parent / "config.json"
COOKIES_FILE = Path(__file__).parent / "cookies.txt"
DOWNLOAD_BASE = Path.home() / "Документы" / "pgups"
LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "pgups.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_LOG_FILES = 3
DEFAULT_WORKERS = 3
MAX_RETRIES = 3
RETRY_DELAY = 3

log_lock = Lock()


def _rotate_log():
    """Rotate log files if they exceed MAX_LOG_SIZE."""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_LOG_SIZE:
            for i in range(MAX_LOG_FILES - 1, 0, -1):
                src = LOG_DIR / f"pgups.{i}.log"
                dst = LOG_DIR / f"pgups.{i + 1}.log"
                if src.exists():
                    src.rename(dst)
            LOG_FILE.rename(LOG_DIR / "pgups.1.log")
    except OSError:
        pass


def _atomic_write(filepath: Path, content: str):
    """Write content atomically using temp file + rename."""
    tmp_path = filepath.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
        tmp_path.replace(filepath)
    except OSError:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def log(msg: str):
    with log_lock:
        print(msg)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            _rotate_log()
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except OSError:
            pass


def sanitize(name: str, strip_задание: bool = False) -> str:
    name = name.strip()
    if strip_задание:
        name = re.sub(r"\s*Задание\s*$", "", name, flags=re.IGNORECASE)
    name = re.sub(r'[\\/:*?"<>|]', " ", name)
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = re.sub(r"\s+", " ", name).strip()
    name = name.rstrip(". ")
    if len(name) > 200:
        name = name[:200]
    return name or "untitled"


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError) as e:
        log(f"[!] Ошибка чтения config.json: {e}")
        return {}


def save_config(cfg: dict):
    try:
        content = json.dumps(cfg, indent=2, ensure_ascii=False)
        _atomic_write(CONFIG_FILE, content)
    except OSError as e:
        log(f"[!] Ошибка записи config.json: {e}")


class PgupsDownloader:
    def __init__(self, courses: list[dict] | None = None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        })
        self.config = load_config()
        default_courses = self.config.get("courses")
        if default_courses:
            self.courses = default_courses
        else:
            self.courses = [
                {"id": "4388", "url": f"{BASE_URL}/course/view.php?id=4388"},
                {"id": "7036", "url": f"{BASE_URL}/course/view.php?id=7036"},
                {"id": "7031", "url": f"{BASE_URL}/course/view.php?id=7031"},
                {"id": "6920", "url": f"{BASE_URL}/course/view.php?id=6920"},
                {"id": "6467", "url": f"{BASE_URL}/course/view.php?id=6467"},
                {"id": "6964", "url": f"{BASE_URL}/course/view.php?id=6964"},
                {"id": "7039", "url": f"{BASE_URL}/course/view.php?id=7039"},
                {"id": "7009", "url": f"{BASE_URL}/course/view.php?id=7009"},
            ]
        if courses:
            self.courses = courses
        self.workers = DEFAULT_WORKERS

        # Load cookies on init so session is ready
        self.load_cookies()

        adapter = requests.adapters.HTTPAdapter(
            max_retries=requests.adapters.Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET", "POST"],
            ),
            pool_connections=10,
            pool_maxsize=10,
            pool_block=False,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _request_with_retry(self, method: str, url: str, max_retries: int = MAX_RETRIES, **kwargs) -> requests.Response:
        last_err = None
        for attempt in range(max_retries):
            try:
                r = self.session.request(method, url, timeout=kwargs.pop("timeout", 15), **{k: v for k, v in kwargs.items() if k != "stream"})
                if r.status_code == 429:
                    wait = RETRY_DELAY * (attempt + 1)
                    log(f"[!] 429 Too Many Requests, ждём {wait}с")
                    time.sleep(wait)
                    continue
                return r
            except requests.exceptions.RequestException as e:
                last_err = e
                log(f"[!] Запрос {method} {url} (попытка {attempt + 1}/{max_retries}) упал: {e}")
                if attempt < max_retries - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
        raise last_err

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._request_with_retry("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self._request_with_retry("POST", url, **kwargs)

    def load_cookies(self) -> bool:
        if not COOKIES_FILE.exists():
            return False
        count = 0
        moodle_found = False
        try:
            with open(COOKIES_FILE, encoding="utf-8") as f:
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
        except (OSError, UnicodeDecodeError) as e:
            log(f"[!] Ошибка чтения cookies.txt: {e}")
            return False
        log(f"[*] Загружено {count} cookies, MoodleSession: {moodle_found}")
        return moodle_found

    def verify_auth(self) -> bool:
        try:
            r = self.get(f"{BASE_URL}/my/", timeout=10)
            login_in_url = "login" in r.url.lower()
            guest_in_text = "Гость" in r.text or "гостевой доступ" in r.text.lower()
            if login_in_url:
                return False
            if guest_in_text:
                return False
            return True
        except Exception:
            return False

    def login(self, username: str, password: str) -> bool:
        log("[*] Попытка входа…")
        try:
            r = self.get(f"{BASE_URL}/login/index.php", timeout=10)
        except Exception:
            return False
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

        try:
            r = self.post(post_url, data=data, allow_redirects=True)
        except Exception:
            return False

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
                try:
                    r = self.post(post_url, data=data, allow_redirects=True)
                except Exception:
                    return False

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
            expires = str(int(cookie.expires)) if cookie.expires and cookie.expires > 0 else str(now_ts)
            lines.append(f"{domain}\t{flag}\t{path}\t{secure}\t{expires}\t{cookie.name}\t{cookie.value}")
        try:
            content = "\n".join(lines) + "\n"
            _atomic_write(COOKIES_FILE, content)
            log(f"[*] Сохранено {len(seen)} cookies")
        except OSError as e:
            log(f"[!] Ошибка сохранения cookies: {e}")

    def get_captcha(self) -> dict | None:
        try:
            r = self.get(f"{MY_BASE_URL}/login", timeout=15)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            form = soup.find("form")
            if not form:
                return None

            token_input = form.find("input", {"name": "_token"})
            if not token_input:
                return None
            csrf_token = token_input.get("value", "")

            captcha_img = soup.find("img", alt=lambda a: a and "captcha" in a.lower())
            captcha_url = urljoin(MY_BASE_URL, captcha_img.get("src", "")) if captcha_img else ""

            captcha_data = b""
            if captcha_url:
                r_img = self.get(captcha_url, timeout=15)
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

    def login_via_portal(self, email: str, password: str, captcha: str = "", remember: bool = True, csrf_token: str = "") -> bool:
        old_cookies = list(self.session.cookies)
        success = False

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
                    if not csrf_token:
                        r = self.get(f"{MY_BASE_URL}/login", timeout=15)
                        soup = BeautifulSoup(r.text, "html.parser")
                        form = soup.find("form")
                        if not form:
                            log("[!] Форма входа на my.pgups.ru не найдена")
                            self._restore_cookies(old_cookies)
                            return False
                        token_input = form.find("input", {"name": "_token"})
                        if not token_input:
                            log("[!] CSRF токен не найден")
                            self._restore_cookies(old_cookies)
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
                r2 = self.post(
                    f"{MY_BASE_URL}/login",
                    data=data,
                    allow_redirects=True,
                    timeout=30,
                )

                is_success = (
                    "/captcha" not in r2.url.lower()
                    and "/login" not in r2.url.lower()
                    and "/verify" not in r2.url.lower()
                )
                if not is_success and ("/verify" in r2.url.lower() or "/captcha" in r2.url.lower()):
                    log(f"[✗] Капча неверна, редирект на /verify — пробуем снова")
                if is_success:
                    log(f"[*] Редирект на: {r2.url}")
                    self._save_session_cookies()
                    log("[*] Запуск SSO через my.pgups.ru/auth/sdo…")
                    sso_r = self.get(f"{MY_BASE_URL}/auth/sdo", timeout=15, allow_redirects=True)
                    self._save_session_cookies()
                    if self.verify_auth():
                        success = True
                        log("[✓] Вход через портал выполнен")
                        break

                    log("[*] SSO не дал авторизации, пробуем принудительный переход")
                    try:
                        force_r = self.get(f"{BASE_URL}/my/", timeout=10, allow_redirects=True)
                        if self.verify_auth():
                            success = True
                            log("[✓] Вход через портал выполнен (принудительно)")
                            break
                    except Exception:
                        pass

                log(f"[✗] Попытка {attempt + 1} не удалась")
                if not captcha:
                    captcha = ""
            except Exception as e:
                log(f"[!] login_via_portal error: {e}")
                if not captcha:
                    captcha = ""

        if not success and not captcha:
            log("[!] Авто-капча не удалась после 8 попыток")
        self._restore_cookies(old_cookies)
        return success

    def _restore_cookies(self, old_cookies: list):
        try:
            for c in old_cookies:
                self.session.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
        except Exception:
            pass

    def get_course_name(self, course_url: str) -> str:
        fallback = f"Курс {course_url.split('=')[-1]}"
        try:
            r = self.get(course_url, timeout=10)
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
        r = self.get(course_url, timeout=10)
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
        r = self.get(assign_url, timeout=10)
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
                files.append({"url": full_url, "filename": filename, "type": "submission"})
        return files

    def get_attachment_files(self, assign_url: str) -> list[dict]:
        r = self.get(assign_url, timeout=10)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        files = []
        seen_urls = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "pluginfile.php" in href and "attachment" in href:
                full_url = href if href.startswith("http") else urljoin(BASE_URL, href)
                if full_url in seen_urls:
                    continue
                seen_urls.add(full_url)
                filename = unquote(full_url.split("/")[-1].split("?")[0])
                if filename:
                    files.append({"url": full_url, "filename": filename, "type": "attachment"})
        return files

    def check_remote_size(self, url: str) -> tuple[int | None, str | None]:
        """Возвращает (размер, etag/md5), если сервер поддерживает."""
        try:
            r = self.get(url, timeout=10, method="HEAD")
            if r.status_code == 200:
                size = r.headers.get("Content-Length")
                etag = r.headers.get("ETag")
                if size:
                    try:
                        return int(size), etag
                    except (ValueError, TypeError):
                        return None, etag
        except Exception:
            pass
        return None, None

    def compute_local_hash(self, filepath: Path) -> str | None:
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def download_file(self, url: str, filename: str, folder: Path, max_retries: int = MAX_RETRIES) -> bool:
        folder.mkdir(parents=True, exist_ok=True)
        filepath = folder / filename

        for attempt in range(max_retries):
            tmp_path = None
            try:
                remote_size, remote_etag = self.check_remote_size(url)

                # Skip if remote size matches and no ETag (reliable indicator)
                if remote_size is not None and remote_etag is None:
                    if filepath.exists() and filepath.stat().st_size == remote_size:
                        return False

                log(f"  ↓ {filename}")
                r = self.get(url, stream=True, timeout=120)
                r.raise_for_status()

                tmp_path = folder / f".{filename}.part"
                with open(tmp_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

                new_size = tmp_path.stat().st_size

                # Only compute hash if remote doesn't provide ETag
                if remote_etag is None:
                    local_hash = self.compute_local_hash(tmp_path)

                    for existing in folder.iterdir():
                        if existing.name.endswith(".part") or not existing.is_file():
                            continue
                        if existing.name != filepath.name:
                            existing_hash = self.compute_local_hash(existing)
                            if existing_hash and local_hash and existing_hash == local_hash:
                                tmp_path.unlink()
                                log(f"     уже есть: {existing.name}")
                                return False

                updated = filepath.exists()
                if updated:
                    filepath.unlink()
                tmp_path.rename(filepath)
                icon = "↻" if updated else "✓"
                log(f"    {icon} {new_size / 1024:.1f} KB")
                return True

            except Exception as e:
                log(f"    ✗ попытка {attempt + 1}/{max_retries} ошибка: {e}")
                if tmp_path and tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
                if attempt < max_retries - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))

        log(f"    ✗ не удалось скачать {filename} после {max_retries} попыток")
        return False

    def _check_submission_and_deadline(self, assign_url: str) -> tuple[bool, str | None]:
        try:
            r = self.get(assign_url, timeout=10)
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
            r = self.get(url, timeout=6)
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

    def check_course(self, course_url: str) -> tuple[list[dict], str]:
        course_id = course_url.split("=")[-1]
        course_name = self.get_course_name(course_url)

        locked_ids = set()
        try:
            r2 = self.get(course_url, timeout=10)
            soup2 = BeautifulSoup(r2.text, "html.parser")
            for act in soup2.find_all("li", class_="activity"):
                info = act.find("div", class_="availabilityinfo")
                if info and "Недоступно" in info.get_text():
                    cm_id = act.get("data-id")
                    iname = act.find("span", class_="instancename")
                    locked_ids.add((cm_id, iname.get_text(strip=True) if iname else ""))
        except Exception:
            pass

        try:
            r = self.get(
                f"{BASE_URL}/grade/report/user/index.php?id={course_id}", timeout=10
            )
            r.raise_for_status()
        except Exception as e:
            log(f"[!] Ошибка загрузки grades: {e}")
            return [], course_name

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
        consecutive_errors = 0

        try:
            while True:
                try:
                    results, _ = self.check_course(course_url)
                    consecutive_errors = 0
                except Exception:
                    consecutive_errors += 1
                    max_wait = min(300, interval * (2 ** consecutive_errors))
                    log(f"[!] Ошибка при проверке, ждём {max_wait}с (ошибок: {consecutive_errors})")
                    time.sleep(max_wait)
                    continue

                curr = fmt(results)
                timestamp = time.strftime("%H:%M:%S")

                if first:
                    self._clear_screen()
                    log(f"\n📡 Мониторинг: {course_name} (id={course_id})")
                    log(f"   Интервал: {interval}с | Выход: Ctrl+C\n")
                    for r in results:
                        log(f"  {r['status']}  {r['name']}")
                    prev = curr
                    first = False
                elif curr != prev:
                    self._clear_screen()
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
        except KeyboardInterrupt:
            log("\n[*] Мониторинг остановлен")

    def _clear_screen(self):
        try:
            subprocess.run(["clear"], check=False, shell=(os.name != "posix"), timeout=2)
        except Exception:
            pass

    def watch(self, course_url: str | None = None, interval: int = 30):
        if not self.ensure_auth("", ""):
            log("[!] Невозможно запустить мониторинг: нет авторизации")
            return
        if course_url:
            self.monitor_course(course_url, interval)
        else:
            log("[!] Укажи ID курса: --course ID")

    def ensure_auth(self, username: str = "", password: str = "") -> bool:
        if self.verify_auth():
            return True

        log("[*] Сессия истекла, пробую восстановить…")

        if not username:
            username = self.config.get("login", "")
            password = self.config.get("password", "")

        if username and password:
            if self.login(username, password):
                return True
            log("[*] Пробую вход через портал с авто-капчей…")
            if self.login_via_portal(username, password):
                return True

        log("[!] Нужна авторизация. Укажи --login / --pass или сохрани в config.json")
        return False

    def collect_tasks(self, download_type: str = "both") -> list[tuple]:
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

                if download_type in ("submission", "both"):
                    files = self.get_submission_files(assign["url"])
                    if files:
                        sub_folder = assign_folder / "submissions" if download_type == "both" else assign_folder
                        log(f"  • {assign_name} ({len(files)} отправка)")
                        course_count += len(files)
                        for f in files:
                            tasks.append((f["url"], f["filename"], sub_folder))

                if download_type in ("attachment", "both"):
                    files = self.get_attachment_files(assign["url"])
                    if files:
                        sub_folder = assign_folder / "attachments" if download_type == "both" else assign_folder
                        log(f"  • {assign_name} ({len(files)} задание)")
                        course_count += len(files)
                        for f in files:
                            tasks.append((f["url"], f["filename"], sub_folder))

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
        app.run(host="127.0.0.1", port=args.port, debug=False)
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
