"""Local-first SQLite persistence for grades, deadlines and downloaded files."""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DATABASE = (
    Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    / "pgups-downloader" / "pgups.sqlite3"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS courses(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items(
    course_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    deadline TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(course_id,item_id)
);
CREATE TABLE IF NOT EXISTS grade_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id TEXT NOT NULL,
    course_name TEXT NOT NULL,
    item_id TEXT NOT NULL,
    item_name TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS grade_events_time ON grade_events(occurred_at DESC);
CREATE TABLE IF NOT EXISTS downloads(
    url TEXT PRIMARY KEY,
    course_name TEXT,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    status TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path = DEFAULT_DATABASE):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.parent.name == "pgups-downloader":
            self.path.parent.chmod(0o700)
        with self._connection() as conn:
            conn.executescript(_SCHEMA)
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(str(self.path), timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=15000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def snapshot_course(self, course_id: str, course_name: str, items: list[dict]) -> list[dict]:
        """Persist a snapshot and return actual status transitions, excluding initial import."""
        events = []
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connection() as conn:
            existed = conn.execute("SELECT 1 FROM courses WHERE id=?", (course_id,)).fetchone() is not None
            conn.execute("INSERT INTO courses(id,name,updated_at) VALUES(?,?,?) "
                         "ON CONFLICT(id) DO UPDATE SET name=excluded.name,updated_at=excluded.updated_at",
                         (course_id,course_name,now))
            for item in items:
                item_id = str(item.get("id") or item["name"])
                prev = conn.execute(
                    "SELECT status FROM items WHERE course_id=? AND item_id=?",
                    (course_id,item_id)
                ).fetchone()
                old = prev["status"] if prev else None
                new = item["status"]
                if old is not None and old != new:
                    item["changed"] = True
                    item["prev_status"] = old
                    events.append({"course_id":course_id,"course_name":course_name,
                                   "item_id":item_id,"item_name":item["name"],
                                   "old_status":old,"new_status":new,"occurred_at":now})
                    conn.execute(
                        "INSERT INTO grade_events(course_id,course_name,item_id,item_name,old_status,new_status,occurred_at) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (course_id,course_name,item_id,item["name"],old,new,now)
                    )
                elif old is None and existed:
                    # A new assignment is also a useful event after an initial import.
                    events.append({"course_id":course_id,"course_name":course_name,
                                   "item_id":item_id,"item_name":item["name"],
                                   "old_status":None,"new_status":new,"occurred_at":now})
                    conn.execute(
                        "INSERT INTO grade_events(course_id,course_name,item_id,item_name,old_status,new_status,occurred_at) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (course_id,course_name,item_id,item["name"],None,new,now)
                    )
                conn.execute(
                    "INSERT INTO items(course_id,item_id,name,status,deadline,updated_at) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(course_id,item_id) DO UPDATE SET "
                    "name=excluded.name,status=excluded.status,deadline=excluded.deadline,updated_at=excluded.updated_at",
                    (course_id,item_id,item["name"],new,item.get("deadline"),now)
                )
        return events

    def cached_courses(self) -> list[dict]:
        """Read the last successful grade snapshot without any network access."""
        with self._lock, self._connection() as conn:
            courses = [dict(row) for row in conn.execute(
                "SELECT id,name,updated_at FROM courses ORDER BY name"
            )]
            items = [dict(row) for row in conn.execute(
                "SELECT course_id,item_id AS id,name,status,deadline FROM items ORDER BY name"
            )]
        indexed = {}
        for item in items:
            indexed.setdefault(item.pop("course_id"), []).append(item)
        result = []
        for course in courses:
            rows = indexed.get(course["id"], [])
            counts = {"passed":0,"failed":0,"submitted":0,"locked":0,"pending":0}
            for item in rows:
                symbol = (item.get("status") or ".")[:1]
                key = {"+":"passed","-":"failed","~":"submitted","#":"locked"}.get(symbol,"pending")
                counts[key] += 1
            result.append({**course,**counts,"items":rows,"stale":True})
        return result

    def history(self, limit: int = 100) -> list[dict]:
        limit = max(1,min(int(limit),500))
        with self._lock, self._connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM grade_events ORDER BY id DESC LIMIT ?", (limit,)
            )]

    def deadlines(self) -> list[dict]:
        with self._lock, self._connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT items.*,courses.name AS course_name FROM items "
                "JOIN courses ON items.course_id=courses.id "
                "WHERE items.deadline IS NOT NULL AND items.deadline != '' ORDER BY items.deadline"
            )]

    def downloaded_files(self, limit: int = 500) -> list[dict]:
        with self._lock, self._connection() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM downloads ORDER BY updated_at DESC LIMIT ?", (max(1,min(limit,2000)),)
            )]

    def record_download(self, url: str, filename: str, path: str, status: str, course_name: str = ""):
        filepath = Path(path)
        size = filepath.stat().st_size if filepath.is_file() else 0
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connection() as conn:
            conn.execute(
                "INSERT INTO downloads(url,filename,path,status,size_bytes,course_name,updated_at) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET "
                "filename=excluded.filename,path=excluded.path,status=excluded.status,"
                "size_bytes=excluded.size_bytes,course_name=excluded.course_name,updated_at=excluded.updated_at",
                (url,filename,path,status,size,course_name,now)
            )
