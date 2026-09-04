"""PGUPS Downloader — download and check coursework from PGUPS."""

from pgups.downloader import PgupsDownloader, main, sanitize, load_config, save_config, log
from pgups.captcha_solver import solve_one_captcha, get_csrf_and_captcha
from pgups.utils import count_statuses, cache_hash, clear_courses_cache
from pgups.config import (
    BASE_URL, MY_BASE_URL, CONFIG_FILE, COOKIES_FILE, DOWNLOAD_BASE,
    LOG_DIR, LOG_FILE, MAX_LOG_SIZE, MAX_LOG_FILES, DEFAULT_WORKERS,
    MAX_RETRIES, RETRY_DELAY,
)

__all__ = [
    "PgupsDownloader",
    "main",
    "sanitize",
    "load_config",
    "save_config",
    "log",
    "solve_one_captcha",
    "get_csrf_and_captcha",
    "count_statuses",
    "cache_hash",
    "clear_courses_cache",
    "BASE_URL",
    "MY_BASE_URL",
    "CONFIG_FILE",
    "COOKIES_FILE",
    "DOWNLOAD_BASE",
    "LOG_DIR",
    "LOG_FILE",
    "MAX_LOG_SIZE",
    "MAX_LOG_FILES",
    "DEFAULT_WORKERS",
    "MAX_RETRIES",
    "RETRY_DELAY",
]
