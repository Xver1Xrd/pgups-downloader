"""Store credentials in the operating-system keyring, never in plaintext config."""
from __future__ import annotations

SERVICE = "pgups-downloader"


def save_password(username: str, password: str) -> None:
    try:
        import keyring
        keyring.set_password(SERVICE, username, password)
    except Exception as exc:
        raise RuntimeError("Не удалось сохранить пароль в системном хранилище секретов") from exc


def get_password(username: str) -> str | None:
    if not username:
        return None
    try:
        import keyring
        return keyring.get_password(SERVICE, username)
    except Exception:
        return None
