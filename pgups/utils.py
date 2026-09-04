import hashlib


def count_statuses(rows: list[dict]) -> dict:
    """Подсчёт статусов из списка заданий."""
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
    return {
        "passed": passed,
        "failed": failed,
        "submitted": submitted,
        "locked": locked,
        "pending": pending,
        "total": passed + failed + submitted + locked + pending,
    }


def cache_hash(data: list) -> str:
    """Хеш списка для инвалидации кеша."""
    raw = str(sorted((c.get("id"), c.get("url")) for c in data))
    return hashlib.sha256(raw.encode()).hexdigest()


def clear_courses_cache(cache: dict) -> None:
    """Очистить кеш курсов полностью."""
    cache["data"] = None
    cache["time"] = 0
    cache["stale"] = None
    cache["stale_time"] = 0
    cache["_key"] = ""
