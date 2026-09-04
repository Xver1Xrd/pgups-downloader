#!/usr/bin/env python3
"""PGUPS Downloader — package configuration and constants."""

from pathlib import Path

BASE_URL = "https://sdo.pgups.ru"
MY_BASE_URL = "https://my.pgups.ru"

CONFIG_FILE = Path(__file__).parent.parent / "config.json"
COOKIES_FILE = Path(__file__).parent.parent / "cookies.txt"
DOWNLOAD_BASE = Path.home() / "Документы" / "pgups"
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_FILE = LOG_DIR / "pgups.log"

MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_LOG_FILES = 3
DEFAULT_WORKERS = 3
MAX_RETRIES = 3
RETRY_DELAY = 3
