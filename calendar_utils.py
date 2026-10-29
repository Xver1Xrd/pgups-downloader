"""Parse PGUPS/Moodle deadline strings and generate a standards-compatible ICS feed."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Europe/Moscow")
MONTHS = {
    "янв":1,"фев":2,"мар":3,"апр":4,"май":5,"мая":5,"июн":6,
    "июл":7,"авг":8,"сен":9,"сент":9,"окт":10,"ноя":11,"дек":12,
}


def parse_deadline(value: str | None) -> datetime | None:
    if not value:
        return None
    text = " ".join(value.lower().replace("\u00a0", " ").split())
    numeric = re.search(r"(\d{1,2})[./-](\d{1,2})[./-](\d{4})(?:\D+(\d{1,2}):(\d{2}))?", text)
    if numeric:
        day, month, year = map(int,numeric.group(1,2,3))
        hour, minute = int(numeric.group(4) or 23), int(numeric.group(5) or 59)
    else:
        named = re.search(r"(\d{1,2})\s+([а-яё]+)\.?\s+(\d{4})(?:\s*(?:г\.?|года)?\s*[,в]?\s*(\d{1,2}):(\d{2}))?", text)
        if not named:
            return None
        day, year = int(named.group(1)), int(named.group(3))
        word = named.group(2)
        month = MONTHS.get(word[:3]) or MONTHS.get(word[:4])
        hour,minute = int(named.group(4) or 23),int(named.group(5) or 59)
        if month is None:
            return None
    try:
        return datetime(year,month,day,hour,minute,tzinfo=TZ)
    except ValueError:
        return None


def _esc(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n","\\n").replace(",", "\\,").replace(";", "\\;")


def create_ics(items: list[dict]) -> str:
    now = datetime.now(TZ).astimezone(ZoneInfo("UTC")).strftime("%Y%m%dT%H%M%SZ")
    output = ["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//PGUPS Downloader//RU","CALSCALE:GREGORIAN","METHOD:PUBLISH"]
    for item in items:
        dt = parse_deadline(item.get("deadline"))
        if not dt:
            continue
        uid = f"{item['course_id']}-{item['item_id']}@pgups-downloader"
        output.extend([
            "BEGIN:VEVENT",
            f"UID:{_esc(uid)}",
            f"DTSTAMP:{now}",
            f"DTSTART:{dt.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            f"SUMMARY:{_esc(item['name'])}",
            f"DESCRIPTION:{_esc(item['course_name'])} — {_esc(item['status'])}",
            "END:VEVENT",
        ])
    output.append("END:VCALENDAR")
    # Fold physical lines to 75 octets as required by RFC 5545.
    folded = []
    for line in output:
        current = ""
        for char in line:
            if len((current + char).encode("utf-8")) > 73:
                folded.append(current)
                current = " " + char
            else:
                current += char
        folded.append(current)
    return "\r\n".join(folded) + "\r\n"
