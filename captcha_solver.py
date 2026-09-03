import io
import cv2
import numpy as np
from collections import Counter
from PIL import Image
from threading import Lock
import ddddocr
from urllib.parse import urljoin
from bs4 import BeautifulSoup

MY_BASE_URL = "https://my.pgups.ru"

_ocr = None
_ocr_lock = Lock()


def get_ocr():
    global _ocr
    if _ocr is None:
        with _ocr_lock:
            if _ocr is None:
                _ocr = ddddocr.DdddOcr(show_ad=False)
    return _ocr


def preprocess_image(img: np.ndarray) -> list[np.ndarray]:
    variants = []
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(otsu)

    _, otsu_inv = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    variants.append(otsu_inv)

    adaptive = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
    variants.append(adaptive)

    adaptive_inv = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 11, 2)
    variants.append(adaptive_inv)

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    _, clahe_otsu = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(clahe_otsu)

    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    _, blur_otsu = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(blur_otsu)

    return variants


def solve_one_captcha(img_bytes: bytes) -> str | None:
    nparr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return None

    ocr = get_ocr()
    results = []

    results.append(ocr.classification(img_bytes))

    for variant in preprocess_image(img):
        _, buf = cv2.imencode(".png", variant)
        results.append(ocr.classification(buf.tobytes()))

    clean = [r.strip() for r in results if r and len(r.strip()) >= 4 and r.strip().isalnum()]
    if clean:
        return Counter(clean).most_common(1)[0][0]
    if results[0]:
        return results[0].strip()
    return None


def get_csrf_and_captcha(session):
    try:
        r = session.get(f"{MY_BASE_URL}/login", timeout=15)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        if not form:
            return "", None
        token_input = form.find("input", {"name": "_token"})
        token = token_input.get("value", "") if token_input else ""
        cap = soup.find("img", alt=lambda a: a and "captcha" in a.lower())
        if not cap:
            return token, None
        captcha_url = urljoin(MY_BASE_URL, cap.get("src", ""))
        if not captcha_url:
            return token, None
        r_img = session.get(captcha_url, timeout=15)
        return token, r_img.content if r_img and r_img.status_code == 200 else None
    except Exception:
        return "", None
