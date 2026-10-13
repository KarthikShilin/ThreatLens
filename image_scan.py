# image_scan.py
"""
ThreatLens Image Scanner
Detects sensitive information in uploaded images:
  - Phone numbers (Indian formats)
  - QR codes (decoded content, no link-following)
  - Vehicle registration numbers (Indian format)
  - Human faces

Libraries used (all lightweight / CPU-only):
  - Pillow          : image decoding / decompression-bomb guard
  - opencv-python   : QR code detection, face detection (YuNet or Haar fallback)
  - rapidocr-onnxruntime : OCR
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import re
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Any

logger = logging.getLogger("threatlens.image_scan")

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError, ExifTags

try:
    from pyzbar import pyzbar
    _HAS_PYZBAR = True
except Exception:
    _HAS_PYZBAR = False

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_BYTES       = 5 * 1024 * 1024          # 5 MB
MAX_PIXELS      = 4000 * 4000              # ~16 MP — guard against decompression bombs
DOWNSCALE_TARGET = 2000                    # long-edge px before processing
OCR_TIMEOUT_S   = 20
DETECT_TIMEOUT_S = 10

ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp"}

# ── Regex patterns ────────────────────────────────────────────────────────────
# Indian mobile: 10 digits starting 6-9, optional +91/0 prefix, spaces/dashes
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:(?:\+91|0091|91|0)[\s\-]?)?"
    r"([6-9]\d{4}[\s\-]?\d{5})"
    r"(?!\d)",
    re.ASCII,
)

# Indian vehicle registration: e.g. KL 07 AB 1234 (spaces optional)
_VREG_RE = re.compile(
    r"\b([A-Z]{2}[\s\-]?\d{1,2}[\s\-]?[A-Z]{1,3}[\s\-]?\d{4})\b",
    re.IGNORECASE | re.ASCII,
)

# ── Box color palette ─────────────────────────────────────────────────────────
_BOX_COLORS = {
    "phone":    (255, 80,  80),   # red-ish
    "qr":       (80,  200, 255),  # cyan
    "vreg":     (255, 180, 30),   # amber
    "face":     (100, 220, 120),  # green
}

# ── Detection result types ────────────────────────────────────────────────────
@dataclass
class Detection:
    kind:    str           # "phone" | "qr" | "vreg" | "face"
    label:   str           # human-readable text shown in box
    value:   str           # raw value (number, decoded QR text, plate text)
    box:     tuple[int, int, int, int]  # x, y, w, h in original image coords


@dataclass
class ScanResult:
    detections:   list[Detection] = field(default_factory=list)
    risk:         str              = "Low"
    findings:     list[dict]       = field(default_factory=list)
    annotated_b64: str             = ""
    exif:         dict             = field(default_factory=dict)
    warnings:     list[str]        = field(default_factory=list)
    error:        Optional[str]    = None


# ── Helper: validate & load image ─────────────────────────────────────────────
def _load_image(raw: bytes) -> tuple[np.ndarray, Image.Image]:
    """
    Validate raw bytes (Pillow decode, size check, MIME check).
    Returns (cv2_bgr_ndarray, pil_image).
    Raises ValueError on bad input.
    """
    if len(raw) > MAX_BYTES:
        raise ValueError("File exceeds 5 MB limit.")

    try:
        pil = Image.open(io.BytesIO(raw))
        pil.verify()                    # raises on malformed / truncated data
    except (UnidentifiedImageError, Exception) as exc:
        raise ValueError(f"Not a valid image: {exc}") from exc

    # Re-open after verify() (verify() closes the stream)
    try:
        pil = Image.open(io.BytesIO(raw))
        pil.load()                      # actually decode pixels
    except Exception as exc:
        raise ValueError(f"Image decode failed: {exc}") from exc

    # MIME check via Pillow format
    fmt_map = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp"}
    mime = fmt_map.get(pil.format or "")
    if not mime:
        raise ValueError("Only JPEG, PNG, and WebP images are accepted.")

    # Decompression bomb guard
    w, h = pil.size
    if w * h > MAX_PIXELS:
        # Downscale instead of rejecting outright
        pil.thumbnail((DOWNSCALE_TARGET, DOWNSCALE_TARGET), Image.LANCZOS)

    # Convert to RGB (drop alpha / palette modes safely)
    pil = pil.convert("RGB")

    # Downscale large images for speed
    lw, lh = pil.size
    if max(lw, lh) > DOWNSCALE_TARGET:
        pil.thumbnail((DOWNSCALE_TARGET, DOWNSCALE_TARGET), Image.LANCZOS)

    cv_img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
    return cv_img, pil


# ── Helper: timeout wrapper ────────────────────────────────────────────────────
def _run_with_timeout(fn, timeout: float):
    """
    Run fn() in a daemon thread; return its result or raise TimeoutError.
    fn must be callable with no arguments.
    """
    result_box: list = [None, None]  # [value, exc]

    def _worker():
        try:
            result_box[0] = fn()
        except Exception as exc:       # noqa: BLE001
            result_box[1] = exc

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"Operation timed out after {timeout}s")
    if result_box[1] is not None:
        raise result_box[1]
    return result_box[0]


# ── OCR ───────────────────────────────────────────────────────────────────────
_ocr_lock = threading.Lock()
_ocr_engine = None
_OCR_WORKER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ocr_worker.py")


def _get_ocr():
    global _ocr_engine
    with _ocr_lock:
        if _ocr_engine is None:
            try:
                from rapidocr_onnxruntime import RapidOCR
                inst = RapidOCR()
                if os.path.isfile(_OCR_WORKER_PATH):
                    _ocr_engine = True
                else:
                    _ocr_engine = inst
            except Exception as exc:
                logger.exception("Failed to initialize RapidOCR engine: %s", exc)
                _ocr_engine = False   # sentinel: unavailable
    return _ocr_engine


def _run_ocr(cv_img: np.ndarray) -> list[tuple[list, str, float]]:
    """
    Returns list of (box_points, text, confidence).
    box_points is a list of 4 [x,y] corner points.
    Caps resolution to 1024px to prevent out-of-memory crashes on memory-constrained servers.
    Executes in a separate subprocess to insulate the main web server process against
    native C++ segfaults or access violations.
    """
    ocr = _get_ocr()
    if not ocr:
        return []

    h, w = cv_img.shape[:2]
    max_dim = max(h, w)
    scale = 1.0
    ocr_img = cv_img
    if max_dim > 1024:
        scale = 1024.0 / max_dim
        new_w = max(int(w * scale), 1)
        new_h = max(int(h * scale), 1)
        ocr_img = cv2.resize(cv_img, (new_w, new_h), interpolation=cv2.INTER_AREA)

    raw_result = []
    # If a callable is directly provided (e.g., mocked in unit tests), run in-process
    if callable(ocr):
        def _call():
            result, _ = ocr(ocr_img)
            return result or []
        try:
            raw_result = _run_with_timeout(_call, OCR_TIMEOUT_S)
        except Exception as exc:
            logger.warning("In-process OCR call failed: %s", exc)
            return []
    else:
        # Run isolated in subprocess
        try:
            success, enc = cv2.imencode(".png", ocr_img)
            if not success:
                return []
            proc = subprocess.run(
                [sys.executable, _OCR_WORKER_PATH],
                input=enc.tobytes(),
                capture_output=True,
                timeout=OCR_TIMEOUT_S,
            )
            if proc.returncode != 0:
                logger.warning(
                    "OCR subprocess crashed or exited with code %s: %s",
                    proc.returncode,
                    proc.stderr.decode("utf-8", errors="replace"),
                )
                return []
            raw_result = json.loads(proc.stdout.decode("utf-8"))
        except Exception as exc:
            logger.warning("OCR subprocess execution failed: %s", exc)
            return []

    if not raw_result:
        return []

    if scale != 1.0:
        inv_scale = 1.0 / scale
        scaled_result = []
        for item in raw_result:
            try:
                box, text, score = item[0], item[1], item[2]
                scaled_box = [[float(pt[0]) * inv_scale, float(pt[1]) * inv_scale] for pt in box]
                scaled_result.append((scaled_box, text, score))
            except Exception:
                scaled_result.append(item)
        return scaled_result

    return raw_result


def _ocr_result_to_text(ocr_result) -> str:
    """Concatenate all OCR text blocks into one string for regex search."""
    parts = []
    for item in ocr_result:
        try:
            parts.append(str(item[1]))
        except (IndexError, TypeError):
            pass
    return " ".join(parts)


def _ocr_box_to_xywh(box_points) -> tuple[int, int, int, int]:
    """Convert 4-point polygon to bounding XYWH."""
    pts = np.array(box_points, dtype=np.float32)
    x, y = int(pts[:, 0].min()), int(pts[:, 1].min())
    w = int(pts[:, 0].max()) - x
    h = int(pts[:, 1].max()) - y
    return x, y, max(w, 1), max(h, 1)


# ── Phone-number detector ─────────────────────────────────────────────────────
def _detect_phones(ocr_result) -> list[Detection]:
    detections: list[Detection] = []
    seen: set[str] = set()

    for item in ocr_result:
        try:
            box_pts = item[0]
            text    = str(item[1])
        except (IndexError, TypeError):
            continue

        for m in _PHONE_RE.finditer(text):
            raw = m.group(0).strip()
            digits = re.sub(r"\D", "", raw)
            if digits in seen:
                continue
            seen.add(digits)
            x, y, w, h = _ocr_box_to_xywh(box_pts)
            detections.append(Detection(
                kind="phone",
                label=f"Phone: {raw}",
                value=raw,
                box=(x, y, w, h),
            ))

    return detections


# ── Vehicle registration detector ─────────────────────────────────────────────
def _detect_vregs(ocr_result) -> list[Detection]:
    detections: list[Detection] = []
    seen: set[str] = set()

    for item in ocr_result:
        try:
            box_pts = item[0]
            text    = str(item[1])
        except (IndexError, TypeError):
            continue

        for m in _VREG_RE.finditer(text):
            raw = m.group(0).strip().upper()
            normalized = re.sub(r"[\s\-]", "", raw)
            if normalized in seen:
                continue
            seen.add(normalized)
            x, y, w, h = _ocr_box_to_xywh(box_pts)
            detections.append(Detection(
                kind="vreg",
                label=f"Plate: {raw}",
                value=raw,
                box=(x, y, w, h),
            ))

    return detections


# ── QR code detector ──────────────────────────────────────────────────────────
def _is_valid_qr_quad(pts: np.ndarray, img_shape: tuple[int, ...], gray: np.ndarray) -> bool:
    """
    Strict geometric and texture validation to prevent false positives when OpenCV
    detect() returns prospective points without decoding a payload.
    """
    h, w = img_shape[:2]
    pts = pts.reshape(-1, 2)
    if len(pts) != 4:
        return False

    # 1. Strictly within image bounds
    if np.any(pts[:, 0] < 0) or np.any(pts[:, 0] > w) or np.any(pts[:, 1] < 0) or np.any(pts[:, 1] > h):
        return False

    # 2. Must be convex quad
    if not cv2.isContourConvex(pts.astype(np.int32).reshape(-1, 1, 2)):
        return False

    bx = int(pts[:, 0].min())
    by = int(pts[:, 1].min())
    bw = int(pts[:, 0].max()) - bx
    bh = int(pts[:, 1].max()) - by

    if bw < 20 or bh < 20:
        return False

    # 3. Maximum size check: QR code shouldn't take more than 50% of image area
    if (bw * bh) > 0.5 * (w * h):
        return False

    # 4. Aspect ratio: QR codes are square, allowing up to perspective tilt
    aspect = bw / float(bh)
    if not (0.65 <= aspect <= 1.55):
        return False

    # 5. Checkerboard texture check
    patch = gray[by:by+bh, bx:bx+bw]
    if patch.size < 400:
        return False

    gx = np.std(cv2.Sobel(patch, cv2.CV_32F, 1, 0))
    gy = np.std(cv2.Sobel(patch, cv2.CV_32F, 0, 1))
    if gx < 20 or gy < 20:
        return False
    if min(gx, gy) / (max(gx, gy) + 1e-5) < 0.45:
        return False

    _, p_bin = cv2.threshold(patch, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    trans_h = np.sum(np.abs(np.diff(p_bin.astype(np.int32), axis=1)) > 0) / float(bw * bh)
    trans_v = np.sum(np.abs(np.diff(p_bin.astype(np.int32), axis=0)) > 0) / float(bw * bh)
    if min(trans_h, trans_v) < 0.08:
        return False

    return True


def _detect_qr(cv_img: np.ndarray) -> list[Detection]:
    """
    Detects QR codes in images using a robust multi-stage pipeline:
      1. Direct decoders (pyzbar + OpenCV QRCodeDetectorAruco + OpenCV QRCodeDetector)
         across multiple image representations (raw grayscale, CLAHE contrast-enhanced,
         sharpened, and 1.5x upscaling).
      2. Verified un-decoded quad fallback: if mathematical Reed-Solomon decoding fails
         (e.g. slight glare, screen photo, minor damage), OpenCV detect() points are accepted
         ONLY if they pass strict convexity, aspect-ratio, boundary, and checkerboard texture tests.
      3. Overlap suppression (IoU / intersection containment) prioritizing decoded values.
    """
    def _call() -> list[tuple[str, tuple[int, int, int, int]]]:
        raw_results: list[tuple[str, tuple[int, int, int, int]]] = []
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        h, w = gray.shape[:2]

        # Preprocessed variants
        variants: list[tuple[np.ndarray, float]] = [(gray, 1.0)]
        try:
            clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
            variants.append((clahe.apply(gray), 1.0))
        except Exception:
            pass
        try:
            kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
            variants.append((cv2.filter2D(gray, -1, kernel), 1.0))
        except Exception:
            pass
        if max(h, w) <= 1600:
            try:
                up = cv2.resize(gray, (0, 0), fx=1.5, fy=1.5, interpolation=cv2.INTER_CUBIC)
                variants.append((up, 1.5))
            except Exception:
                pass

        # 1. Pyzbar pass (Primary decoder for valid QR codes)
        if _HAS_PYZBAR:
            for var, sf in variants:
                try:
                    decoded = pyzbar.decode(var, symbols=[pyzbar.ZBarSymbol.QRCODE])
                    for item in decoded:
                        if item.data:
                            try:
                                text = item.data.decode("utf-8", errors="replace").strip()
                            except Exception:
                                text = str(item.data).strip()
                            if text:
                                rect = item.rect
                                bx = int(rect.left / sf)
                                by = int(rect.top / sf)
                                bw = int(rect.width / sf)
                                bh = int(rect.height / sf)
                                if bw > 0 and bh > 0:
                                    raw_results.append((text, (bx, by, bw, bh)))
                except Exception:
                    pass
                if raw_results:
                    break

        # 2. OpenCV Detectors (QRCodeDetectorAruco + QRCodeDetector)
        detectors: list[Any] = []
        if hasattr(cv2, "QRCodeDetectorAruco"):
            try:
                detectors.append(cv2.QRCodeDetectorAruco())
            except Exception:
                pass
        try:
            detectors.append(cv2.QRCodeDetector())
        except Exception:
            pass

        for det in detectors:
            for var, sf in variants:
                # Multi-detect & decode — ONLY if decoded text is present
                try:
                    retval, decoded_info, points, _ = det.detectAndDecodeMulti(var)
                    if retval and points is not None and len(points) > 0:
                        for d_text, pts in zip(decoded_info, points):
                            if d_text and d_text.strip():
                                pts = np.array(pts, dtype=np.float32).reshape(-1, 2) / sf
                                bx = int(pts[:, 0].min())
                                by = int(pts[:, 1].min())
                                bw = int(pts[:, 0].max()) - bx
                                bh = int(pts[:, 1].max()) - by
                                if bw > 0 and bh > 0:
                                    raw_results.append((d_text.strip(), (bx, by, bw, bh)))
                except Exception:
                    pass

                # Single detect & decode — ONLY if decoded text is present
                try:
                    d_text, pts, _ = det.detectAndDecode(var)
                    if d_text and d_text.strip() and pts is not None and len(pts) > 0:
                        pts = np.array(pts, dtype=np.float32).reshape(-1, 2) / sf
                        bx = int(pts[:, 0].min())
                        by = int(pts[:, 1].min())
                        bw = int(pts[:, 0].max()) - bx
                        bh = int(pts[:, 1].max()) - by
                        if bw > 0 and bh > 0:
                            raw_results.append((d_text.strip(), (bx, by, bw, bh)))
                except Exception:
                    pass

                # detect() only — only if NO decoded results yet AND passes strict quad validation
                if not raw_results:
                    try:
                        ret, pts = det.detect(var)
                        if ret and pts is not None and len(pts) > 0:
                            pts_orig = np.array(pts, dtype=np.float32).reshape(-1, 2) / sf
                            if _is_valid_qr_quad(pts_orig, (h, w), gray):
                                bx = int(pts_orig[:, 0].min())
                                by = int(pts_orig[:, 1].min())
                                bw = int(pts_orig[:, 0].max()) - bx
                                bh = int(pts_orig[:, 1].max()) - by
                                raw_results.append(("[QR Code Detected]", (bx, by, bw, bh)))
                    except Exception:
                        pass

        def _boxes_overlap(b1: tuple[int, int, int, int], b2: tuple[int, int, int, int], threshold: float = 0.25) -> bool:
            xA = max(b1[0], b2[0])
            yA = max(b1[1], b2[1])
            xB = min(b1[0] + b1[2], b2[0] + b2[2])
            yB = min(b1[1] + b1[3], b2[1] + b2[3])
            iw = max(0, xB - xA)
            ih = max(0, yB - yA)
            if iw <= 0 or ih <= 0:
                return False
            ia = iw * ih
            a1 = b1[2] * b1[3]
            a2 = b2[2] * b2[3]
            return (ia / float(a1 + 1e-6) > threshold) or (ia / float(a2 + 1e-6) > threshold)

        # Prioritize detections with actual decoded content over generic placeholder
        raw_results.sort(
            key=lambda r: (r[0] != "[QR Code Detected]" and not r[0].startswith("[") and len(r[0]) > 0),
            reverse=True,
        )

        final_results: list[tuple[str, tuple[int, int, int, int]]] = []
        for val, box in raw_results:
            overlap = False
            for f_val, f_box in final_results:
                if _boxes_overlap(box, f_box):
                    overlap = True
                    break
            if not overlap:
                final_results.append((val, box))

        return final_results

    try:
        results = _run_with_timeout(_call, DETECT_TIMEOUT_S)
    except Exception as exc:
        logger.exception("QR detection failed or timed out: %s", exc)
        return []

    detections = []
    seen: set[str] = set()
    for data, (x, y, w, h) in results:
        x = max(0, x)
        y = max(0, y)
        w = max(1, w)
        h = max(1, h)

        key = f"{data}:{x // 10}:{y // 10}"
        if key in seen:
            continue
        seen.add(key)

        if data and not data.startswith("["):
            short = data if len(data) <= 60 else data[:57] + "…"
            label = f"QR: {short}"
        else:
            label = "QR Code"

        detections.append(Detection(
            kind="qr",
            label=label,
            value=data,
            box=(x, y, w, h),
        ))

    return detections




# ── Face detector ─────────────────────────────────────────────────────────────
_face_lock = threading.Lock()
_face_detector = None   # None = not tried; False = unavailable
_YUNET_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "face_detection_yunet_2023mar.onnx"
)


def _get_face_detector():
    global _face_detector
    with _face_lock:
        if _face_detector is None:
            if os.path.isfile(_YUNET_MODEL_PATH):
                try:
                    # Try YuNet (OpenCV 4.8+)
                    fd = cv2.FaceDetectorYN.create(
                        model=_YUNET_MODEL_PATH,
                        config="",
                        input_size=(320, 320),
                        score_threshold=0.7,
                        nms_threshold=0.3,
                        top_k=5000,
                    )
                    _face_detector = ("yunet", fd)
                except Exception as exc:
                    logger.exception("Failed to initialize YuNet face detector: %s", exc)
            if _face_detector is None:
                # Fallback: Haar cascade
                try:
                    if hasattr(cv2, "CascadeClassifier"):
                        cc = cv2.CascadeClassifier(
                            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
                        )
                        if not cc.empty():
                            _face_detector = ("haar", cc)
                except Exception as exc:
                    logger.exception("Failed to initialize Haar face detector: %s", exc)
            if _face_detector is None:
                _face_detector = False
    return _face_detector


def _detect_faces(cv_img: np.ndarray) -> list[Detection]:
    detector = _get_face_detector()
    if not detector:
        return []

    kind, obj = detector

    def _call():
        if kind == "yunet":
            h, w = cv_img.shape[:2]
            obj.setInputSize((w, h))
            _, faces = obj.detect(cv_img)
            results = []
            if faces is not None:
                for face in faces:
                    fx, fy, fw, fh = int(face[0]), int(face[1]), int(face[2]), int(face[3])
                    results.append((fx, fy, fw, fh))
            return results
        else:  # haar
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            faces = obj.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
            if len(faces) == 0:
                return []
            return [(int(x), int(y), int(w), int(h)) for x, y, w, h in faces]

    try:
        boxes = _run_with_timeout(_call, DETECT_TIMEOUT_S)
    except Exception:
        return []

    detections = []
    for i, (x, y, w, h) in enumerate(boxes or []):
        detections.append(Detection(
            kind="face",
            label=f"Face #{i + 1}",
            value=f"face_{i + 1}",
            box=(x, y, w, h),
        ))
    return detections


# ── Annotation ────────────────────────────────────────────────────────────────
def _annotate(cv_img: np.ndarray, detections: list[Detection]) -> str:
    """Draw colored boxes + labels; return base64-encoded PNG."""
    img = cv_img.copy()
    font      = cv2.FONT_HERSHEY_SIMPLEX
    font_scale = max(0.4, min(cv_img.shape[1] / 1200, 0.9))
    thickness = max(1, int(cv_img.shape[1] / 600))

    for det in detections:
        color = _BOX_COLORS.get(det.kind, (200, 200, 200))
        x, y, w, h = det.box
        # Clamp to image bounds
        x = max(0, x); y = max(0, y)
        x2 = min(cv_img.shape[1], x + w)
        y2 = min(cv_img.shape[0], y + h)

        cv2.rectangle(img, (x, y), (x2, y2), color, thickness + 1)

        # Label background
        label = det.label
        (tw, th), baseline = cv2.getTextSize(label, font, font_scale, thickness)
        ly = max(y - 6, th + 4)
        cv2.rectangle(img, (x, ly - th - 4), (x + tw + 6, ly + baseline), color, -1)
        cv2.putText(img, label, (x + 3, ly), font, font_scale,
                    (0, 0, 0), thickness, cv2.LINE_AA)

    # Encode to PNG
    success, buf = cv2.imencode(".png", img)
    if not success:
        raise RuntimeError("Failed to encode annotated image")
    return base64.b64encode(buf.tobytes()).decode("ascii")


# ── Risk & findings builder ────────────────────────────────────────────────────
def _build_risk_and_findings(detections: list[Detection]) -> tuple[str, list[dict]]:
    kinds_found: set[str] = {d.kind for d in detections}
    n_kinds = len(kinds_found)

    if n_kinds == 0:
        risk = "Low"
    elif n_kinds == 1:
        risk = "Medium"
    else:
        risk = "High"

    findings: list[dict] = []

    kind_meta = {
        "phone": {
            "title":       "Phone Number(s) Detected",
            "explanation": (
                "One or more Indian mobile phone numbers may be present in this image. "
                "Sharing images containing phone numbers could expose personal contact "
                "information to unintended recipients."
            ),
            "fix": "Blur or crop areas containing phone numbers before sharing this image.",
        },
        "qr": {
            "title":       "QR Code(s) Detected",
            "explanation": (
                "One or more QR codes were found. QR codes may encode payment links, "
                "personal profile URLs, or other sensitive data that could be exploited "
                "if this image is shared publicly."
            ),
            "fix": "Remove or obscure QR codes from the image before sharing. Verify the encoded content is non-sensitive.",
        },
        "vreg": {
            "title":       "Vehicle Registration Number(s) Detected",
            "explanation": (
                "Text that may be a vehicle registration number was found. Registration "
                "numbers can be used to look up vehicle ownership records and may compromise "
                "location privacy or personal identity."
            ),
            "fix": "Blur or redact vehicle number plates in the image before sharing.",
        },
        "face": {
            "title":       "Human Face(s) Detected",
            "explanation": (
                "One or more faces were detected. Sharing images containing identifiable "
                "faces without consent may raise privacy or legal concerns depending on "
                "jurisdiction and context."
            ),
            "fix": "Blur or pixelate faces in the image before sharing if consent has not been obtained.",
        },
    }

    for kind in ("phone", "qr", "vreg", "face"):
        if kind not in kinds_found:
            continue
        meta = kind_meta[kind]
        vals = [d.value for d in detections if d.kind == kind]
        findings.append({
            "kind":        kind,
            "title":       meta["title"],
            "plain_explanation": meta["explanation"],
            "recommended_fix":   meta["fix"],
            "values":      vals,
            "count":       len(vals),
        })

    return risk, findings


# ── EXIF extraction ───────────────────────────────────────────────────────────

# EXIF classification tiers
# HIGH: GPS data (latitude/longitude/altitude)
# MEDIUM: device/camera/lens serial numbers, Artist, XPAuthor, Copyright,
#         ImageDescription, XPComment, HostComputer
# INFO ONLY: Make, Model, Software, DateTime*, etc. (shown in table, no risk bump)

_MEDIUM_EXIF_TAGS = {
    "Artist",
    "XPAuthor",
    "Copyright",
    "ImageDescription",
    "XPComment",
    "HostComputer",
    "CameraSerialNumber",
    "BodySerialNumber",
    "LensSerialNumber",
    "SerialNumber",
}

# Human-readable GPS tag map (inside GPSInfo IFD)
_GPS_TAG_MAP: dict[int, str] = {
    t: name for name, t in ExifTags.GPSTAGS.items()
}


def _classify_exif_tag(tag_name: str) -> str:
    """Return 'high', 'medium', or 'info' for an EXIF tag name."""
    if tag_name.startswith("GPS") or tag_name == "GPSInfo":
        return "high"
    lower = tag_name.lower()
    if tag_name in _MEDIUM_EXIF_TAGS or "serialnumber" in lower or "serial_number" in lower:
        return "medium"
    return "info"


def _rational_to_float(val: Any) -> float:
    """Convert IFDRational / tuple-rational to Python float."""
    try:
        if hasattr(val, 'numerator'):          # IFDRational
            return val.numerator / val.denominator if val.denominator else 0.0
        if isinstance(val, tuple) and len(val) == 2:  # (num, den)
            return val[0] / val[1] if val[1] else 0.0
        return float(val)
    except Exception:
        return 0.0


def _gps_dms_to_decimal(dms: Any, ref: str) -> Optional[float]:
    """Convert GPS DMS tuple to decimal degrees."""
    try:
        d = _rational_to_float(dms[0])
        m = _rational_to_float(dms[1])
        s = _rational_to_float(dms[2])
        decimal = d + m / 60.0 + s / 3600.0
        if ref in ('S', 'W'):
            decimal = -decimal
        return round(decimal, 7)
    except Exception:
        return None


def _format_raw_exif_val(raw_val: Any) -> str:
    """Convert rational / bytes / tuples to clean display text."""
    try:
        if isinstance(raw_val, bytes):
            display = raw_val.decode("utf-8", errors="replace").strip("\x00")
        elif hasattr(raw_val, 'numerator'):
            display = str(_rational_to_float(raw_val))
        elif isinstance(raw_val, tuple):
            display = ", ".join(str(_rational_to_float(v)) if hasattr(v, 'numerator') else str(v)
                               for v in raw_val)
        else:
            display = str(raw_val)
    except Exception:
        display = repr(raw_val)

    if len(display) > 200:
        display = display[:197] + "…"
    return display


def _extract_exif(pil_img: Image.Image) -> dict:
    """
    Extract all EXIF tags from a PIL image.
    Returns a dict with:
      - 'fields':  list of {tag, value, sensitive, tier} records
      - 'gps':     {lat, lon, alt, map_url} if GPS present, else {}
      - 'has_sensitive': bool
    """
    result: dict = {"fields": [], "gps": {}, "has_sensitive": False}

    try:
        exif_data = pil_img.getexif()          # Pillow >= 6.0 unified API
    except Exception:
        return result

    if not exif_data:
        return result

    # Build tag-name map
    tag_name_map: dict[int, str] = {
        k: v for k, v in ExifTags.TAGS.items()
    }

    gps_ifd: dict = {}
    seen_tags: set[str] = set()

    def _process_tag(tag_name: str, raw_val: Any):
        if tag_name in seen_tags:
            return
        seen_tags.add(tag_name)

        display = _format_raw_exif_val(raw_val)
        tier = _classify_exif_tag(tag_name)
        sensitive = tier in ("high", "medium")

        result["fields"].append({
            "tag":       tag_name,
            "value":     display,
            "sensitive": sensitive,
            "tier":      tier,
        })

    # 1. Main IFD
    for tag_id, raw_val in exif_data.items():
        tag_name = tag_name_map.get(tag_id, f"Tag_{tag_id}")

        if tag_name == "GPSInfo" or tag_id == 34853:
            try:
                if isinstance(raw_val, dict):
                    gps_ifd = raw_val
                else:
                    gps_ifd = dict(exif_data.get_ifd(tag_id))
            except Exception:
                pass
            continue

        if tag_name in ("ExifOffset", "Exif IFD") or tag_id == 34665:
            # Sub-IFD handled below
            continue

        _process_tag(tag_name, raw_val)

    # 2. Exif sub-IFD (tag 34665)
    try:
        sub_exif = exif_data.get_ifd(34665)
        if sub_exif:
            for sub_tag_id, sub_raw in sub_exif.items():
                sub_name = tag_name_map.get(sub_tag_id, f"Tag_{sub_tag_id}")
                if sub_name == "GPSInfo" or sub_tag_id == 34853:
                    if not gps_ifd:
                        try:
                            gps_ifd = dict(sub_raw) if isinstance(sub_raw, dict) else dict(exif_data.get_ifd(34853))
                        except Exception:
                            pass
                    continue
                _process_tag(sub_name, sub_raw)
    except Exception:
        pass

    # 3. GPS IFD
    if not gps_ifd:
        try:
            gps_ifd = dict(exif_data.get_ifd(34853))
        except Exception:
            pass

    if gps_ifd:
        lat_val  = gps_ifd.get(2)      # GPSLatitude
        lat_ref  = gps_ifd.get(1, '')  # GPSLatitudeRef
        lon_val  = gps_ifd.get(4)      # GPSLongitude
        lon_ref  = gps_ifd.get(3, '')  # GPSLongitudeRef
        alt_val  = gps_ifd.get(6)      # GPSAltitude

        lat = _gps_dms_to_decimal(lat_val, str(lat_ref)) if lat_val else None
        lon = _gps_dms_to_decimal(lon_val, str(lon_ref)) if lon_val else None
        alt: Optional[float] = None
        try:
            alt = round(_rational_to_float(alt_val), 2) if alt_val else None
        except Exception:
            pass

        if lat is not None and lon is not None:
            result["gps"] = {
                "lat": lat,
                "lon": lon,
                "alt": alt,
                "map_url": f"https://maps.google.com/?q={lat},{lon}",
            }
            # Add GPS fields to the field list for display
            result["fields"].append({"tag": "GPS Latitude",  "value": f"{lat}°",  "sensitive": True, "tier": "high"})
            result["fields"].append({"tag": "GPS Longitude", "value": f"{lon}°",  "sensitive": True, "tier": "high"})
            if alt is not None:
                result["fields"].append({"tag": "GPS Altitude", "value": f"{alt} m", "sensitive": True, "tier": "high"})
        else:
            for gps_tag_id, gps_raw in gps_ifd.items():
                gps_name = _GPS_TAG_MAP.get(gps_tag_id, f"GPS_{gps_tag_id}")
                gps_display = _format_raw_exif_val(gps_raw)
                result["fields"].append({"tag": gps_name, "value": gps_display, "sensitive": True, "tier": "high"})

    # Determine if any sensitive metadata exists
    result["has_sensitive"] = any(f["tier"] in ("high", "medium") for f in result["fields"]) or bool(result.get("gps"))

    # Sort: high tier first, then medium, then info, then alphabetically by tag
    tier_order = {"high": 0, "medium": 1, "info": 2}
    result["fields"].sort(key=lambda f: (tier_order.get(f.get("tier"), 2), f["tag"]))

    return result


# ── In-memory EXIF Stripper ───────────────────────────────────────────────────
def strip_exif(raw_bytes: bytes) -> tuple[bytes, str, str]:
    """
    Remove all metadata (EXIF, ICC profile, XMP, comments) from image bytes
    by re-encoding pixel data only.
    Processed fully in memory; never touches disk.

    Returns (cleaned_bytes, media_type, file_extension).
    Raises ValueError on invalid or oversized images.
    """
    if len(raw_bytes) > MAX_BYTES:
        raise ValueError("File exceeds 5 MB limit.")
    if len(raw_bytes) == 0:
        raise ValueError("Empty file received.")

    try:
        pil = Image.open(io.BytesIO(raw_bytes))
        pil.verify()
    except Exception as exc:
        raise ValueError(f"Not a valid image: {exc}") from exc

    try:
        pil = Image.open(io.BytesIO(raw_bytes))
        pil.load()
    except Exception as exc:
        raise ValueError(f"Failed to decode image pixels: {exc}") from exc

    if pil.width * pil.height > MAX_PIXELS:
        raise ValueError(f"Image resolution exceeds maximum allowable dimensions ({MAX_PIXELS} px).")

    fmt = pil.format
    if not fmt:
        raise ValueError("Unrecognized image format.")
    fmt_upper = fmt.upper()
    if fmt_upper not in ("JPEG", "PNG", "WEBP"):
        raise ValueError(f"Unsupported image format: {fmt}. Only JPEG, PNG, and WebP are supported.")

    mode = pil.mode
    if fmt_upper == "JPEG" and mode not in ("RGB", "L"):
        clean_img = pil.convert("RGB")
    else:
        clean_img = Image.new(mode, pil.size)
        clean_img.paste(pil)

    clean_img.info.clear()

    out_buf = io.BytesIO()
    save_kwargs = {}
    if fmt_upper == "JPEG":
        save_kwargs["quality"] = 95
        media_type = "image/jpeg"
        ext = ".jpg"
    elif fmt_upper == "PNG":
        media_type = "image/png"
        ext = ".png"
    elif fmt_upper == "WEBP":
        media_type = "image/webp"
        ext = ".webp"
    else:
        raise ValueError(f"Unsupported image format: {fmt}")

    clean_img.save(out_buf, format=fmt_upper, **save_kwargs)
    return out_buf.getvalue(), media_type, ext


# ── Public API ────────────────────────────────────────────────────────────────
def scan_image(raw_bytes: bytes) -> ScanResult:
    """
    Main entry point.
    Accepts raw image bytes; returns a ScanResult.
    Never writes to disk.
    Never raises an uncaught exception.
    """
    try:
        cv_img, pil_img = _load_image(raw_bytes)
    except ValueError as exc:
        return ScanResult(error=str(exc))
    except Exception as exc:
        logger.exception("Failed to load image: %s", exc)
        return ScanResult(error="Could not decode image")

    try:
        all_detections: list[Detection] = []
        warnings: list[str] = []

        # ── EXIF extraction (before any downscaling side-effects) ─────────────────
        exif_data: dict = {}
        try:
            pil_orig = Image.open(io.BytesIO(raw_bytes))
            pil_orig.load()
            exif_data = _extract_exif(pil_orig)
        except Exception as exc:
            logger.exception("EXIF extraction failed: %s", exc)
            exif_data = {"fields": [], "gps": {}, "has_sensitive": False}

        # ── OCR (one pass, reuse for phone + vreg) ────────────────────────────────
        if not _get_ocr():
            warnings.append("Phone numbers and vehicle numbers were NOT checked (OCR detector unavailable).")
        else:
            try:
                ocr_result = _run_ocr(cv_img)
                all_detections.extend(_detect_phones(ocr_result))
                all_detections.extend(_detect_vregs(ocr_result))
            except Exception as exc:
                logger.exception("OCR detection failed: %s", exc)
                warnings.append("Phone numbers and vehicle numbers were NOT checked (OCR detector failed).")

        # ── QR ────────────────────────────────────────────────────────────────────
        try:
            all_detections.extend(_detect_qr(cv_img))
        except Exception as exc:
            logger.exception("QR detection failed: %s", exc)

        # ── Faces ─────────────────────────────────────────────────────────────────
        try:
            all_detections.extend(_detect_faces(cv_img))
        except Exception as exc:
            logger.exception("Face detection failed: %s", exc)

        # ── Risk + findings ───────────────────────────────────────────────────────
        risk, findings = _build_risk_and_findings(all_detections)

        # ── EXIF findings & risk bump ─────────────────────────────────────────────
        has_high_exif = (
            bool(exif_data.get("gps")) or
            any(f.get("tier") == "high" for f in exif_data.get("fields", []))
        )
        has_medium_exif = any(f.get("tier") == "medium" for f in exif_data.get("fields", []))

        if has_high_exif:
            risk = "High"
            gps_vals = []
            if exif_data.get("gps") and exif_data["gps"].get("lat") is not None:
                gps = exif_data["gps"]
                coord_str = f"{gps['lat']}°, {gps['lon']}°"
                if gps.get("alt") is not None:
                    coord_str += f" ({gps['alt']} m)"
                gps_vals.append(coord_str)
            else:
                for f in exif_data.get("fields", []):
                    if f.get("tier") == "high":
                        gps_vals.append(f"{f['tag']}: {f['value']}")

            findings.append({
                "kind":              "gps",
                "title":             "GPS Location Data Detected",
                "plain_explanation": "This photo contains GPS coordinates that may reveal where it was taken.",
                "recommended_fix":   "Remove metadata before sharing.",
                "values":            gps_vals,
                "count":             len(gps_vals) if gps_vals else 1,
            })

        if has_medium_exif:
            if risk == "Low":
                risk = "Medium"
            med_fields = [f for f in exif_data.get("fields", []) if f.get("tier") == "medium"]
            med_vals = [f"{f['tag']}: {f['value']}" for f in med_fields]
            findings.append({
                "kind":              "exif_meta",
                "title":             "Device & Creator Metadata Detected",
                "plain_explanation": "This photo contains device serial numbers or creator information that may identify your device or personal identity.",
                "recommended_fix":   "Remove metadata before sharing.",
                "values":            med_vals,
                "count":             len(med_vals),
            })

        # ── Annotated image ───────────────────────────────────────────────────────
        try:
            annotated_b64 = _annotate(cv_img, all_detections)
        except Exception as exc:
            logger.exception("Image annotation failed: %s", exc)
            annotated_b64 = ""

        return ScanResult(
            detections=all_detections,
            risk=risk,
            findings=findings,
            annotated_b64=annotated_b64,
            exif=exif_data,
            warnings=warnings,
        )
    except Exception as exc:
        logger.exception("Internal error in scan_image: %s", exc)
        return ScanResult(error="Internal error processing image")


# ── Serialisation helper ──────────────────────────────────────────────────────
def scan_result_to_dict(result: ScanResult) -> dict:
    """Convert ScanResult to a JSON-serialisable dict."""
    if result.error:
        return {"error": result.error}

    has_sensitive_exif = bool(result.exif.get("has_sensitive", False))
    has_warnings = bool(result.warnings)
    return {
        "risk":            result.risk,
        "findings":        result.findings,
        "detections": [
            {
                "kind":  d.kind,
                "label": d.label,
                "value": d.value,
                "box":   list(d.box),
            }
            for d in result.detections
        ],
        "annotated_image": result.annotated_b64,
        "clean":           len(result.detections) == 0 and not has_sensitive_exif and not has_warnings,
        "exif":            result.exif,
        "warnings":        result.warnings,
    }
