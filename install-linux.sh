#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
VENV="$ROOT/.venv"

"$PYTHON" -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r "$ROOT/requirements.txt"

mkdir -p "$HOME/.local/bin"
printf -v PYTHON_QUOTED '%q' "$VENV/bin/python"
printf -v SCRIPT_QUOTED '%q' "$ROOT/pgups_downloader.py"
printf '#!/usr/bin/env bash\nexec %s %s "$@"\n' "$PYTHON_QUOTED" "$SCRIPT_QUOTED" > "$HOME/.local/bin/pgups"
chmod 755 "$HOME/.local/bin/pgups"
printf 'Установлено: %s\n' "$HOME/.local/bin/pgups"
printf 'Запуск: pgups --web\n'
printf 'Откройте http://127.0.0.1:5000 в браузере.\n'
printf 'Если команда pgups не найдена, добавьте ~/.local/bin в PATH.\n'
