#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import subprocess
import hashlib
import tempfile
import threading
from pathlib import Path
from urllib.parse import urljoin, unquote, urlsplit, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import requests
from captcha_solver import auto_solve_captcha, solve_one_captcha, get_csrf_and_captcha

BASE_URL = "https://sdo.pgups.ru"
MY_BASE_URL = "https://my.pgups.ru"
CONFIG_FILE = Path(__file__).parent / "config.json"
COOKIES_FILE = Path(__file__).parent / "cookies.txt"
DOWNLOAD_BASE = Path.home() / "Документы" / "pgups"
LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "pgups.log"
DEFAULT_WORKERS = 3
MAX_RETRIES = 3
RETRY_DELAY = 3

log_lock = Lock()


def log(msg: str):
    with log_lock:
        print(msg)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        try:
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


def public_url(url: str) -> str:
    """Log origins and paths without exposing SSO query parameters or fragments."""
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def trusted_moodle_url(url: str) -> bool:
    """Only accept HTTPS links to the Moodle origin (no userinfo or custom ports)."""
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname == "sdo.pgups.ru"
                and not parsed.username and not parsed.password and parsed.port in (None, 443))
    except ValueError:
        return False


def safe_filename(name: str) -> str:
    """Discard untrusted URL path components and unsafe filesystem characters."""
    name = unquote(str(name)).replace("\\", "/").split("/")[-1]
    if name.strip() in ("", ".", ".."):
        return "unnamed-file"
    return sanitize(name)


def _atomic_private_write(path: Path, contents: str):
    """Never expose partially-written credential/cookie files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".pgups-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.chmod(tmp_name, 0o600)
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


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
        _atomic_private_write(
            CONFIG_FILE,
            json.dumps(cfg, indent=2, ensure_ascii=False),
        )
    except OSError as e:
        log(f"[!] Ошибка записи config.json: {e}")
        raise


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
        defaults = [
            {"id": cid, "url": f"{BASE_URL}/course/view.php?id={cid}"}
            for cid in ("4388", "7036", "7031", "6920", "6467", "6964", "7039", "7009")
        ]
        self.courses = list(courses if courses is not None else self.config.get("courses", defaults))
        self.workers = DEFAULT_WORKERS
        self._owner_thread = threading.get_ident()
        self._thread_local = threading.local()
        self._session_version = 0

        # Load cookies on init so session is ready
        self.load_cookies()

        self.session.mount("https://", requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=0))
        self.session.mount("http://", requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=0))

    def _http_session(self) -> requests.Session:
        """Use an independent requests.Session and cookie jar in worker threads."""
        if threading.get_ident() == self._owner_thread:
            return self.session
        local = self._thread_local
        if getattr(local, "version", -1) != self._session_version:
            old = getattr(local, "session", None)
            if old is not None:
                old.close()
            client = requests.Session()
            client.headers.update(self.session.headers)
            client.cookies.update(self.session.cookies)
            client.mount("https://", requests.adapters.HTTPAdapter(pool_connections=3, pool_maxsize=3, max_retries=0))
            client.mount("http://", requests.adapters.HTTPAdapter(pool_connections=3, pool_maxsize=3, max_retries=0))
            local.session = client
            local.version = self._session_version
        return local.session

    def _request_with_retry(self, method: str, url: str, max_retries: int = MAX_RETRIES, **kwargs) -> requests.Response:
        method = method.upper()
        # Authentication POST requests may have side effects: never retry them automatically.
        attempts = max_retries if method in ("GET", "HEAD") else 1
        timeout = kwargs.pop("timeout", 15)
        last_error = None
        for attempt in range(attempts):
            try:
                r = self._http_session().request(method, url, timeout=timeout, **kwargs)
                if r.status_code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                    retry_after = r.headers.get("Retry-After", "")
                    try:
                        delay = min(max(float(retry_after), 0), 30)
                    except ValueError:
                        delay = min(RETRY_DELAY * (attempt + 1), 15)
                    r.close()
                    time.sleep(delay)
                    continue
                return r
            except requests.exceptions.RequestException as exc:
                last_error = exc
                if attempt == attempts - 1:
                    break
                time.sleep(min(RETRY_DELAY * (attempt + 1), 15))
        raise last_error or requests.exceptions.RequestException("Request failed")

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._request_with_retry("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self._request_with_retry("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self._request_with_retry("POST", url, **kwargs)

    def load_cookies(self) -> bool:
        if not COOKIES_FILE.exists():
            log("[DEBUG] cookies.txt not found")
            return False
        count = 0
        moodle_found = False
        try:
            with open(COOKIES_FILE, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    http_only = line.startswith("#HttpOnly_")
                    if http_only:
                        line = line[len("#HttpOnly_"):]
                    elif line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 7:
                        domain, _, path, secure, expires, name, value = parts[:7]
                        if domain.lstrip(".") not in ("sdo.pgups.ru", "my.pgups.ru", "pgups.ru"):
                            continue
                        try:
                            expiry = int(expires)
                        except ValueError:
                            expiry = None
                        if expiry and expiry < time.time():
                            continue
                        cookie = requests.cookies.create_cookie(
                            name=name, value=value, domain=domain, path=path or "/",
                            secure=secure.upper() == "TRUE", expires=expiry,
                            rest={"HttpOnly": True} if http_only else {}
                        )
                        self.session.cookies.set_cookie(cookie)
                        count += 1
                        if "sdo.pgups.ru" in domain and name == "MoodleSession":
                            moodle_found = True
                            log(f"[DEBUG] Loaded MoodleSession cookie for {domain}")
                        elif "sdo.pgups.ru" in domain:
                            log(f"[DEBUG] Loaded cookie {name} for {domain}")
        except (OSError, UnicodeDecodeError) as e:
            log(f"[!] Ошибка чтения cookies.txt: {e}")
            return False
        self._session_version += 1
        log(f"[*] Загружено {count} cookies, MoodleSession: {moodle_found}")
        return moodle_found

    def verify_auth(self) -> bool:
        """Verify response is an authenticated Moodle page, not a redirect/error."""
        try:
            r = self.get(f"{BASE_URL}/my/", timeout=10)
            if r.status_code != 200 or not trusted_moodle_url(r.url):
                return False
            path = urlsplit(r.url).path.lower()
            if path.startswith("/login") or path.startswith("/auth"):
                return False
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text(" ", strip=True).lower()
            if ("гостевой доступ" in text or "you are currently using guest access" in text
                    or soup.select_one('form[action*="login/index.php"]')
                    or soup.select_one('input[name="logintoken"]')):
                return False
            # Moodle usually exposes a user menu or logout action when signed in.
            if (soup.select_one(".usermenu, #user-menu-toggle, a[href*='/login/logout.php']")
                    or soup.select_one('[data-action="user-menu-toggle"]')):
                return True
            # Some custom Moodle themes have no standard menu; a valid /my/
            # dashboard plus a MoodleSession cookie remains a secondary signal.
            cookies = self._http_session().cookies
            has_session = any(c.name == "MoodleSession" and c.domain.lstrip(".") == "sdo.pgups.ru"
                              for c in cookies)
            return has_session and path.startswith("/my")
        except (requests.RequestException, ValueError):
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

    def publish_session_cookies(self):
        """Publish the active request thread's cookies for subsequent web requests."""
        active = self._http_session()
        if active is not self.session:
            self.session.cookies.clear()
            self.session.cookies.update(active.cookies)
        self._session_version += 1

    def _save_session_cookies(self):
        self.publish_session_cookies()
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
            prefix = "#HttpOnly_" if cookie._rest.get("HttpOnly") else ""
            lines.append(f"{prefix}{domain}\t{flag}\t{path}\t{secure}\t{expires}\t{cookie.name}\t{cookie.value}")
        try:
            _atomic_private_write(COOKIES_FILE, "\n".join(lines) + "\n")
            self._session_version += 1
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
        old_cookies = list(self._http_session().cookies)
        success = False

        for attempt in range(8 if not captcha else 1):
            try:
                if not captcha:
                    log(f"[*] Авто-капча: попытка {attempt + 1}/8…")
                    token, captcha_img = get_csrf_and_captcha(self._http_session())
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

                log("[*] Отправка формы входа на my.pgups.ru…")
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
                    log(f"[*] Редирект на: {public_url(r2.url)}")
                    log(f"[DEBUG] cookies после входа: {[(c.name, c.domain) for c in self.session.cookies]}")
                    log("[*] Запуск SSO через my.pgups.ru/auth/sdo…")
                    sso_r = self.get(f"{MY_BASE_URL}/auth/sdo", timeout=15, allow_redirects=True)
                    log(f"[DEBUG] SSO response: url={public_url(sso_r.url)}, status={sso_r.status_code}")
                    log(f"[DEBUG] cookies после SSO: {[(c.name, c.domain) for c in self.session.cookies]}")
                    log(f"[DEBUG] cookies после SSO (перед сохранением): {[(c.name, c.domain) for c in self.session.cookies]}")
                    if self.verify_auth():
                        self._save_session_cookies()
                        success = True
                        log("[✓] Вход через портал выполнен")
                        break

                    log(f"[DEBUG] verify_auth упал, пробуем принудительный переход на sdo.pgups.ru")
                    try:
                        force_r = self.get(f"{BASE_URL}/my/", timeout=10, allow_redirects=True)
                        log(f"[DEBUG] Принудительный переход: url={public_url(force_r.url)}")
                        if self.verify_auth():
                            self._save_session_cookies()
                            success = True
                            log("[✓] Вход через портал выполнен (принудительно)")
                            break
                    except Exception as e2:
                        log(f"[DEBUG] Принудительный переход не удался: {e2}")

                log(f"[✗] Попытка {attempt + 1} не удалась")
                if not captcha:
                    captcha = ""
            except Exception as e:
                log(f"[!] login_via_portal error: {e}")
                if not captcha:
                    captcha = ""

        if not success and not captcha:
            log("[!] Авто-капча не удалась после 8 попыток")
        if not success:
            self._restore_cookies(old_cookies)
        return success

    def _restore_cookies(self, old_cookies: list):
        try:
            active = self._http_session()
            active.cookies.clear()
            for c in old_cookies:
                active.cookies.set_cookie(c)
            if active is self.session:
                self._session_version += 1
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

    def discover_courses(self) -> list[dict]:
        """Find course links visible to the authenticated user on Moodle."""
        found = {}
        for page in ("/my/courses.php", "/my/"):
            try:
                r = self.get(f"{BASE_URL}{page}", timeout=15)
                r.raise_for_status()
                if not trusted_moodle_url(r.url) or "/login/" in r.url:
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                for link in soup.select('a[href]'):
                    url = urljoin(BASE_URL, link["href"])
                    if not trusted_moodle_url(url):
                        continue
                    parsed = urlsplit(url)
                    if parsed.path != "/course/view.php":
                        continue
                    cid = parse_qs(parsed.query).get("id", [""])[0]
                    if cid.isascii() and cid.isdigit():
                        found[cid] = {"id":cid,"url":f"{BASE_URL}/course/view.php?id={cid}"}
                if found:
                    break
            except requests.RequestException as exc:
                log(f"[DISCOVER] Ошибка чтения списка курсов: {exc}")
        return sorted(found.values(), key=lambda item: int(item["id"]))

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
                full_url = urljoin(BASE_URL, href)
                if not trusted_moodle_url(full_url):
                    continue
                assignments.append({
                    "id": assign_id,
                    "name": name,
                    "url": full_url,
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
                full_url = urljoin(BASE_URL, href)
                if not trusted_moodle_url(full_url) or full_url in seen_urls:
                    continue
                seen_urls.add(full_url)
                filename = safe_filename(urlsplit(full_url).path.split("/")[-1])
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
                full_url = urljoin(BASE_URL, href)
                if not trusted_moodle_url(full_url) or full_url in seen_urls:
                    continue
                seen_urls.add(full_url)
                filename = safe_filename(urlsplit(full_url).path.split("/")[-1])
                if filename:
                    files.append({"url": full_url, "filename": filename, "type": "attachment"})
        return files

    def _trusted_file_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Reject cross-origin redirects before transmitting authenticated requests."""
        for _ in range(6):
            parsed = urlsplit(url)
            if not trusted_moodle_url(url):
                raise ValueError("Недоверенный адрес файла или перенаправления")
            if method == "HEAD":
                response = self.head(url, allow_redirects=False, **kwargs)
            else:
                response = self.get(url, allow_redirects=False, **kwargs)
            if response.status_code not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise ValueError("Перенаправление без Location")
            url = urljoin(url, location)
        raise ValueError("Слишком много перенаправлений")

    def check_remote_size(self, url: str) -> tuple[int | None, str | None]:
        """Возвращает (размер, etag/md5), если сервер поддерживает."""
        try:
            r = self._trusted_file_request("HEAD", url, timeout=10)
            if r.status_code == 200:
                size = r.headers.get("Content-Length")
                etag = r.headers.get("ETag")
                if size:
                    return int(size), etag
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

    def download_file(self, url: str, filename: str, folder: Path,
                      max_retries: int = MAX_RETRIES,
                      cancel_event: threading.Event | None = None) -> bool:
        """Stream to a private temporary file, verify, then atomically replace."""
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        filename = safe_filename(filename)
        parsed_url = urlsplit(url)
        if not trusted_moodle_url(url):
            log("[!] Заблокирован URL скачивания вне sdo.pgups.ru")
            return False
        filepath = folder / filename

        for attempt in range(max(1, max_retries)):
            if cancel_event is not None and cancel_event.is_set():
                return False
            tmp_path = None
            try:
                # Never overwrite a symlink outside the intended directory.
                if filepath.is_symlink():
                    raise ValueError("Отказ от записи через символическую ссылку")
                remote_size, remote_etag = self.check_remote_size(url)
                log(f"  ↓ {filename}")
                with self._trusted_file_request("GET", url, stream=True, timeout=(10, 120)) as r:
                    r.raise_for_status()
                    if "text/html" in r.headers.get("Content-Type", "").lower():
                        raise ValueError("Сервер вернул HTML вместо файла (возможно, истекла сессия)")
                    if r.headers.get("Content-Length", "").isdigit() and int(r.headers["Content-Length"]) > 1024 * 1024 * 1024:
                        raise ValueError("Файл превышает допустимый размер (1 ГиБ)")
                    with tempfile.NamedTemporaryFile(mode="wb", dir=folder, prefix=".pgups-", suffix=".part", delete=False) as target:
                        tmp_path = Path(target.name)
                        new_hash = hashlib.sha256()
                        total = 0
                        for chunk in r.iter_content(chunk_size=65536):
                            if cancel_event is not None and cancel_event.is_set():
                                return False
                            if not chunk:
                                continue
                            target.write(chunk)
                            new_hash.update(chunk)
                            total += len(chunk)
                            if total > 1024 * 1024 * 1024:
                                raise ValueError("Файл превышает допустимый размер (1 ГиБ)")
                        target.flush()
                        os.fsync(target.fileno())

                length = r.headers.get("Content-Length")
                if length and length.isdigit() and total != int(length):
                    raise IOError(f"Неполная загрузка: {total} / {length} байт")
                if remote_size is not None and total != remote_size:
                    raise IOError("Размер загруженного файла отличается от размера на сервере")
                digest = new_hash.hexdigest()
                if filepath.exists() and self.compute_local_hash(filepath) == digest:
                    tmp_path.unlink()
                    return False

                # Duplicate hashes are checked only inside this assignment folder.
                for existing in folder.iterdir():
                    if existing == tmp_path or existing == filepath or existing.is_symlink() or not existing.is_file():
                        continue
                    if existing.stat().st_size == total and self.compute_local_hash(existing) == digest:
                        tmp_path.unlink()
                        log(f"    уже есть: {existing.name}")
                        return False

                if cancel_event is not None and cancel_event.is_set():
                    return False
                if filepath.is_symlink():
                    raise ValueError("Целевой путь стал символической ссылкой")
                os.replace(tmp_path, filepath)
                tmp_path = None
                log(f"    ✓ {total / 1024:.1f} KB")
                return True
            except (OSError, ValueError, requests.RequestException) as e:
                log(f"    ✗ попытка {attempt + 1}/{max_retries}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(min(RETRY_DELAY * (attempt + 1), 15))
            finally:
                if tmp_path is not None:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except OSError:
                        pass
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
                    candidate = urljoin(BASE_URL, a["href"])
                    assign_url = candidate if trusted_moodle_url(candidate) else None
                    break

            locked = is_locked(name_raw, cm_id)

            if grade_raw and grade_raw not in ("-", "( Пусто )"):
                if letter in ("Отл", "Хор", "Удовл"):
                    status = f"+ {letter} ({score})"
                elif letter == "Неуд":
                    status = f"- Неуд ({score})"
                else:
                    status = f"? {grade_raw}"
                rows_data.append({"id": cm_id or name, "name": name, "status": status, "url": assign_url})
            elif locked:
                rows_data.append({"id": cm_id or name, "name": name, "status": "# заблокирован", "url": assign_url})
            elif type_prefix == "Задание" and assign_url:
                check_submission.append({
                    "id": cm_id or name,
                    "name": name,
                    "url": assign_url,
                })
            else:
                rows_data.append({"id": cm_id or name, "name": name, "status": ". не пройдено", "url": assign_url})

        if check_submission:
            with ThreadPoolExecutor(max_workers=5) as pool:
                fut = {
                    pool.submit(self._check_submission_and_deadline, item["url"]): item["url"]
                    for item in check_submission
                }
                results = {}
                for f in as_completed(fut):
                    url = fut[f]
                    has_sub, dl = f.result()
                    results[url] = (has_sub, dl)
            for item in check_submission:
                has_sub, dl = results.get(item["url"], (False, None))
                if has_sub:
                    rows_data.append({"id": item["id"], "name": item["name"], "status": "~ сдано / не проверено", "url": item["url"]})
                else:
                    rows_data.append({"id": item["id"], "name": item["name"], "status": ". не сдано", "url": item["url"]})
                if dl:
                    rows_data[-1]["deadline"] = dl

        return rows_data, course_name

    def check_all(self):
        from storage import Store
        store = Store()
        log("\n" + "=" * 55)
        log("PGUPS — Проверка успеваемости")
        log("=" * 55)

        for course in self.courses:
            results, course_name = self.check_course(course["url"])
            if not results:
                continue
            store.snapshot_course(course["id"], course_name, results)
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

        try:
            while True:
                results, _ = self.check_course(course_url)
                curr = fmt(results)
                from storage import Store
                Store().snapshot_course(course_id, course_name, results)
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
            subprocess.run(["clear"], check=False, shell=(os.name != "posix"))
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
        log(f"[DEBUG] ensure_auth called, username='{username[:10] if username else ''}...'")
        if self.verify_auth():
            log(f"[DEBUG] Auth OK from cookies")
            return True

        log("[*] Сессия истекла, пробую восстановить…")

        if not username:
            username = self.config.get("login", "")
            from secret_store import get_password
            password = get_password(username) or self.config.get("password", "")

        if username and password:
            log(f"[DEBUG] Trying login with saved credentials")
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
                        log(f"  • {assign_name} ({len(files)} отправка)")
                        course_count += len(files)
                        for f in files:
                            tasks.append((f["url"], f["filename"], assign_folder))

                if download_type in ("attachment", "both"):
                    files = self.get_attachment_files(assign["url"])
                    if files:
                        log(f"  • {assign_name} ({len(files)} задание)")
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
            from secret_store import save_password
            try:
                save_password(username, password)
            except RuntimeError as exc:
                log(f"[!] {exc}. Вход продолжается без сохранения пароля.")
                save_login = False
            self.config["login"] = username
            self.config.pop("password", None)
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

        from storage import Store
        index = Store()
        downloaded = 0
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            fut = {pool.submit(self.download_file, url, name, folder): (url, name, folder)
                   for url, name, folder in tasks}
            for f in as_completed(fut):
                url, name, folder = fut[f]
                try:
                    success = f.result()
                except Exception as exc:
                    log(f"[!] Ошибка скачивания {name}: {exc}")
                    success = False
                if success:
                    downloaded += 1
                status = "downloaded" if success else ("skipped" if (folder / name).is_file() else "failed")
                index.record_download(url, name, str(folder / name), status, folder.parent.name)

        log(f"\n{'=' * 55}")
        skipped = len(tasks) - downloaded
        log(f"Готово! Скачано: {downloaded}, пропущено: {skipped}")
        log(f"Папка: {DOWNLOAD_BASE}")
        log(f"{'=' * 55}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Скачиватор лаб PGUPS")
    parser.add_argument("--login", help="Логин")
    parser.add_argument("--pass", dest="password", help="Пароль (небезопасно: виден в истории команд)")
    parser.add_argument("--prompt-password", action="store_true", help="Запросить пароль без отображения")
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
    if args.workers is not None and not (1 <= args.workers <= 10):
        parser.error("--workers должен быть от 1 до 10")
    if args.interval < 15:
        parser.error("--interval должен быть не меньше 15 секунд")
    if args.prompt_password:
        import getpass
        args.password = getpass.getpass("Пароль ЭИОС: ")

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
        from web_app import app, start_scheduler
        start_scheduler()
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
            from storage import Store
            if results:
                Store().snapshot_course(args.course, name, results)
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
