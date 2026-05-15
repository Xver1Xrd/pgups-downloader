import io
import cv2
import numpy as np
from collections import Counter
from PIL import Image
import ddddocr
from urllib.parse import urljoin
from bs4 import BeautifulSoup

MY_BASE_URL = "https://my.pgups.ru"

_ocr = None


def get_ocr():
    global _ocr
    if _ocr is None:
        _ocr = ddddocr.DdddOcr(show_ad=False)
    return _ocr


def solve_one_captcha(img_bytes: bytes) -> str | None:
    nparr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return None

    ocr = get_ocr()
    results = []

    results.append(ocr.classification(img_bytes))

    b = img[:, :, 0]
    _, tb = cv2.threshold(b, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    _, buf = cv2.imencode(".png", tb)
    results.append(ocr.classification(buf.tobytes()))

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, tg = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    _, buf = cv2.imencode(".png", tg)
    results.append(ocr.classification(buf.tobytes()))

    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    _, tr = cv2.threshold(rgb[:, :, 0], 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    _, buf = cv2.imencode(".png", tr)
    results.append(ocr.classification(buf.tobytes()))

    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    _, th = cv2.threshold(hsv[:, :, 2], 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    _, buf = cv2.imencode(".png", th)
    results.append(ocr.classification(buf.tobytes()))

    clean = [r.strip() for r in results if r and len(r.strip()) >= 4 and r.strip().isalnum()]
    if clean:
        return Counter(clean).most_common(1)[0][0]
    return results[0] if results[0] else None


def auto_solve_captcha(session, max_retries: int = 4) -> str | None:
    for attempt in range(max_retries):
        try:
            r = session.get(f"{MY_BASE_URL}/login", timeout=15)
            soup = BeautifulSoup(r.text, "html.parser")
            cap = soup.find("img", alt=lambda a: a and "captcha" in a.lower())
            if not cap:
                continue
            captcha_url = urljoin(MY_BASE_URL, cap.get("src", ""))
            r_img = session.get(captcha_url, timeout=15)
            text = solve_one_captcha(r_img.content)
            if text:
                return text
        except Exception:
            continue
    return None


def get_csrf_and_captcha(session):
    r = session.get(f"{MY_BASE_URL}/login", timeout=15)
    soup = BeautifulSoup(r.text, "html.parser")
    form = soup.find("form")
    token = form.find("input", {"name": "_token"}).get("value", "") if form else ""
    cap = soup.find("img", alt=lambda a: a and "captcha" in a.lower())
    captcha_url = urljoin(MY_BASE_URL, cap.get("src", "")) if cap else ""
    r_img = session.get(captcha_url, timeout=15) if captcha_url else None
    return token, r_img.content if r_img else None
