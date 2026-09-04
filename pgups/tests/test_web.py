#!/usr/bin/env python3
"""Tests for web.py factory pattern and metrics."""

import base64
import time
from pgups.web import create_app, get_downloader, _metrics_lock, _metrics


def _basic_auth_header(user, password):
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


class TestAppFactory:
    """Test create_app() factory function."""

    def test_create_app_returns_flask(self):
        """create_app() should return a Flask app instance."""
        app = create_app(testing=True)
        assert app is not None
        assert hasattr(app, "url_map")

    def test_app_routes_exist(self):
        """App should have all expected routes."""
        app = create_app(testing=True)
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        assert "/health" in rules
        assert "/metrics" in rules
        assert "/api/csrf-token" in rules
        assert "/api/auth/status" in rules
        assert "/api/courses" in rules
        assert "/api/download" in rules


class TestGetDownloader:
    """Test get_downloader() singleton access."""

    def test_get_downloader_returns_instance(self):
        """get_downloader() should return a PgupsDownloader instance."""
        dl = get_downloader()
        assert dl is not None

    def test_get_downloader_returns_same_instance(self):
        """get_downloader() should return the same instance on repeated calls."""
        dl1 = get_downloader()
        dl2 = get_downloader()
        assert dl1 is dl2


class TestMetrics:
    """Test metrics tracking."""

    def test_metrics_initialized(self):
        """Metrics should have expected initial keys."""
        with _metrics_lock:
            assert "total_requests" in _metrics
            assert "total_downloads" in _metrics
            assert "total_files_downloaded" in _metrics
            assert "total_errors" in _metrics

    def test_metrics_increment(self):
        """_increment_metric() should increase values."""
        from pgups.web import _increment_metric
        from pgups.web import _metrics_lock
        from pgups.web import _metrics

        with _metrics_lock:
            initial = _metrics.get("test_count", 0)

        _increment_metric("test_count")
        _increment_metric("test_count")

        with _metrics_lock:
            assert _metrics["test_count"] == initial + 2

    def test_metrics_update(self):
        """_update_metric() should set new values."""
        from pgups.web import _update_metric
        from pgups.web import _metrics_lock
        from pgups.web import _metrics

        with _metrics_lock:
            _metrics["test_value"] = 0

        _update_metric("test_value", 42)

        with _metrics_lock:
            assert _metrics["test_value"] == 42

    def test_health_endpoint(self):
        """Test health endpoint returns correct structure."""
        app = create_app(testing=True)
        client = app.test_client()
        resp = client.get("/health", headers=_basic_auth_header("test", "test"))
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data
        assert data["status"] == "ok"
        assert "timestamp" in data
        assert "authenticated" in data

    def test_metrics_endpoint(self):
        """Test metrics endpoint returns correct structure."""
        app = create_app(testing=True)
        client = app.test_client()
        resp = client.get("/metrics", headers=_basic_auth_header("test", "test"))
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_requests" in data
        assert "uptime_seconds" in data
        assert "courses_count" in data
