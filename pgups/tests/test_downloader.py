"""Tests for pgups.downloader.sanitize function."""

import pytest
from pgups.downloader import sanitize


class TestSanitize:
    def test_basic_strip(self):
        assert sanitize("  hello  ") == "hello"

    def test_strip_задание_suffix(self):
        assert sanitize("Лабораторная 1 Задание", strip_задание=True) == "Лабораторная 1"
        assert sanitize("Лабораторная 1 задание", strip_задание=True) == "Лабораторная 1"
        assert sanitize("Лабораторная 1 ЗАДАНИЕ", strip_задание=True) == "Лабораторная 1"

    def test_strip_задание_disabled(self):
        assert sanitize("Задание 1 Задание", strip_задание=False) == "Задание 1 Задание"

    def test_no_strip_задание_by_default(self):
        assert sanitize("Лабораторная 1 Задание") == "Лабораторная 1 Задание"

    def test_remove_invalid_chars(self):
        assert sanitize("file<name>.txt") == "file name .txt"
        assert sanitize('file"name', strip_задание=False) == "file name"

    def test_remove_control_chars(self):
        result = sanitize("hello\x00world")
        assert "hello" in result
        assert "world" in result

    def test_consecutive_spaces(self):
        assert sanitize("hello    world") == "hello world"

    def test_strip_trailing_punctuation(self):
        assert sanitize("hello.") == "hello"
        assert sanitize("hello..") == "hello"
        assert sanitize("hello. ") == "hello"

    def test_max_length(self):
        long_name = "a" * 300
        result = sanitize(long_name)
        assert len(result) <= 200

    def test_empty_returns_untitled(self):
        assert sanitize("") == "untitled"
        assert sanitize("   ") == "untitled"
        assert sanitize("\\") == "untitled"

    def test_combined_operations(self):
        result = sanitize("  Lab 1  Задание  ", strip_задание=True)
        assert result == "Lab 1"

    def test_special_chars_with_strip(self):
        result = sanitize("Lab: 1/ Задание", strip_задание=True)
        assert result == "Lab 1"
