"""Tests for pgups.utils functions."""

import pytest
from pgups.utils import count_statuses, cache_hash, clear_courses_cache


class TestCountStatuses:
    def test_all_statuses(self):
        rows = [
            {"status": "+ Отл (95)"},
            {"status": "- Неуд (30)"},
            {"status": "~ сдано / не проверено"},
            {"status": "# заблокирован"},
            {"status": ". не пройдено"},
        ]
        result = count_statuses(rows)
        assert result["passed"] == 1
        assert result["failed"] == 1
        assert result["submitted"] == 1
        assert result["locked"] == 1
        assert result["pending"] == 1
        assert result["total"] == 5

    def test_empty_rows(self):
        result = count_statuses([])
        assert result["passed"] == 0
        assert result["failed"] == 0
        assert result["submitted"] == 0
        assert result["locked"] == 0
        assert result["pending"] == 0
        assert result["total"] == 0

    def test_only_passed(self):
        rows = [
            {"status": "+ Отл (95)"},
            {"status": "+ Хор (85)"},
            {"status": "+ Удовл (70)"},
        ]
        result = count_statuses(rows)
        assert result["passed"] == 3
        assert result["total"] == 3

    def test_status_prefixes(self):
        rows = [
            {"status": "+ something"},
            {"status": "- something"},
            {"status": "~ something"},
            {"status": "# something"},
            {"status": "? some text"},
            {"status": ". some text"},
            {"status": "unknown prefix"},
        ]
        result = count_statuses(rows)
        assert result["passed"] == 1
        assert result["failed"] == 1
        assert result["submitted"] == 1
        assert result["locked"] == 1
        assert result["pending"] == 3


class TestCacheHash:
    def test_same_data_same_hash(self):
        data = [
            {"id": "1", "url": "https://example.com/1"},
            {"id": "2", "url": "https://example.com/2"},
        ]
        h1 = cache_hash(data)
        h2 = cache_hash(data)
        assert h1 == h2

    def test_different_data_different_hash(self):
        data1 = [
            {"id": "1", "url": "https://example.com/1"},
        ]
        data2 = [
            {"id": "2", "url": "https://example.com/2"},
        ]
        h1 = cache_hash(data1)
        h2 = cache_hash(data2)
        assert h1 != h2

    def test_different_order_same_hash(self):
        data1 = [
            {"id": "1", "url": "https://example.com/1"},
            {"id": "2", "url": "https://example.com/2"},
        ]
        data2 = [
            {"id": "2", "url": "https://example.com/2"},
            {"id": "1", "url": "https://example.com/1"},
        ]
        h1 = cache_hash(data1)
        h2 = cache_hash(data2)
        assert h1 == h2

    def test_empty_list(self):
        result = cache_hash([])
        assert len(result) == 64  # SHA-256 hex digest length

    def test_returns_hex_string(self):
        data = [{"id": "1", "url": "https://example.com/1"}]
        result = cache_hash(data)
        assert all(c in "0123456789abcdef" for c in result)


class TestClearCoursesCache:
    def test_clears_all_fields(self):
        cache = {
            "data": {"courses": []},
            "time": 1000,
            "stale": {"courses": []},
            "stale_time": 500,
            "_key": "some_key",
        }
        clear_courses_cache(cache)
        assert cache["data"] is None
        assert cache["time"] == 0
        assert cache["stale"] is None
        assert cache["stale_time"] == 0
        assert cache["_key"] == ""

    def test_does_not_affect_other_keys(self):
        cache = {
            "data": {"courses": []},
            "time": 1000,
            "other_key": "should remain",
        }
        clear_courses_cache(cache)
        assert cache["data"] is None
        assert cache["time"] == 0
        assert cache["other_key"] == "should remain"
