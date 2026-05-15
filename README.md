# pgups-downloader

Скачивание лабораторных работ и проверка успеваемости в ЭИОС ПГУПС.

## Установка

```
python3 -m venv venv
venv/bin/pip install requests beautifulsoup4 flask Pillow opencv-python-headless ddddocr
```

## CLI

```
venv/bin/python pgups_downloader.py --login user@domain --pass password --save-login
venv/bin/python pgups_downloader.py --check
venv/bin/python pgups_downloader.py --check --course 6964
venv/bin/python pgups_downloader.py --workers 5
```

## Веб-интерфейс

```
venv/bin/python pgups_downloader.py --web
```

Открыть http://127.0.0.1:5000

При запуске сервер сам логинится: распознаёт капчу, проходит SSO через my.pgups.ru/auth/sdo, сохраняет cookies. Результаты проверки кешируются на 5 минут.

## Как работает авторизация

Сервер загружает страницу my.pgups.ru/login, достаёт CSRF-токен и капчу. Капча распознаётся ddddocr (три варианта предобработки, голосование). Отправляется POST с реквизитами. Если my.pgups.ru ответил редиректом на /dashboard — капча принята. Затем выполняется GET /auth/sdo, который запускает SSO и устанавливает MoodleSession.

## config.json

```json
{
  "login": "email",
  "password": "password",
  "courses": [
    {"id": "4388", "url": "https://sdo.pgups.ru/course/view.php?id=4388"}
  ]
}
```

## Статусы заданий

- `+` сдано с баллом
- `-` не зачтено
- `~` загружено, не проверено
- `#` заблокировано
- `.` не сдано / не пройдено

## Файлы на диске

```
~/Downloads/pgups/
  Название курса/
    Название работы/
      файлы
```

## Зависимости

- Python 3.10+
- requests, beautifulsoup4
- flask
- Pillow, opencv-python-headless, ddddocr
