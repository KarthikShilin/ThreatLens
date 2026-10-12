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
import re
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Any

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError, ExifTags

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


def _get_ocr():
    global _ocr_engine
    with _ocr_lock:
        if _ocr_engine is None:
            try:
                from rapidocr_onnxruntime import RapidOCR
                _ocr_engine = RapidOCR()
            except ImportError:
                _ocr_engine = False   # sentinel: unavailable
    return _ocr_engine


def _run_ocr(cv_img: np.ndarray) -> list[tuple[list, str, float]]:
    """
    Returns list of (box_points, text, confidence).
    box_points is a list of 4 [x,y] corner points.
    """
    ocr = _get_ocr()
    if not ocr:
        return []

    def _call():
        result, _ = ocr(cv_img)
        return result or []

    try:
        return _run_with_timeout(_call, OCR_TIMEOUT_S)
    except Exception:
        return []


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
def _detect_qr(cv_img: np.ndarray) -> list[Detection]:
    detections: list[Detection] = []

    def _call():
        detector = cv2.QRCodeDetector()
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        data, points, _ = detector.detectAndDecode(gray)
        results = []
        if data and points is not None:
            results.append((data, points))
        # Try multi-detect
        try:
            retval, data_list, points_list, _ = detector.detectAndDecodeMulti(gray)
            if retval and data_list:
                for d, p in zip(data_list, points_list):
                    if d and d != (results[0][0] if results else None):
                        results.append((d, p))
        except Exception:
            pass
        return results

    try:
        results = _run_with_timeout(_call, DETECT_TIMEOUT_S)
    except Exception:
        return []

    seen: set[str] = set()
    for data, points in results:
        if data in seen:
            continue
        seen.add(data)
        pts = np.array(points, dtype=np.float32).reshape(-1, 2)
        x = int(pts[:, 0].min())
        y = int(pts[:, 1].min())
        w = int(pts[:, 0].max()) - x
        h = int(pts[:, 1].max()) - y
        # Truncate very long QR payloads for the label
        short = data if len(data) <= 60 else data[:57] + "…"
        detections.append(Detection(
            kind="qr",
            label=f"QR: {short}",
            value=data,
            box=(x, y, max(w, 1), max(h, 1)),
        ))

    return detections


# ── Face detector ─────────────────────────────────────────────────────────────
_face_lock = threading.Lock()
_face_detector = None   # None = not tried; False = unavailable


def _get_face_detector():
    global _face_detector
    with _face_lock:
        if _face_detector is None:
            try:
                # Try YuNet (OpenCV 4.8+)
                fd = cv2.FaceDetectorYN.create(
                    model="face_detection_yunet_2023mar.onnx",
                    config="",
                    input_size=(320, 320),
                    score_threshold=0.7,
                    nms_threshold=0.3,
                    top_k=5000,
                )
                _face_detector = ("yunet", fd)
            except Exception:
                # Fallback: Haar cascade
                try:
                    cc = cv2.CascadeClassifier(
                        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
                    )
                    if cc.empty():
                        _face_detector = False
                    else:
                        _face_detector = ("haar", cc)
                except Exception:
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

# EXIF tag IDs considered privacy-sensitive
_SENSITIVE_TAG_NAMES = {
    "GPSInfo", "GPSLatitude", "GPSLongitude", "GPSAltitude",
    "GPSLatitudeRef", "GPSLongitudeRef", "GPSTimeStamp", "GPSDateStamp",
    "GPSProcessingMethod", "GPSMeasureMode",
    "Make", "Model", "Software",
    "Artist", "Copyright", "ImageDescription",
    "CameraSerialNumber", "BodySerialNumber", "LensSerialNumber",
    "DateTime", "DateTimeOriginal", "DateTimeDigitized",
    "HostComputer", "XPAuthor", "XPComment",
}

# Human-readable GPS tag map (inside GPSInfo IFD)
_GPS_TAG_MAP: dict[int, str] = {
    t: name for name, t in ExifTags.GPSTAGS.items()
}


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


def _extract_exif(pil_img: Image.Image) -> dict:
    """
    Extract all EXIF tags from a PIL image.
    Returns a dict with:
      - 'fields':  list of {tag, value, sensitive} records
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

    for tag_id, raw_val in exif_data.items():
        tag_name = tag_name_map.get(tag_id, f"Tag_{tag_id}")

        if tag_name == "GPSInfo":
            # raw_val may already be a dict from getexif()
            try:
                if isinstance(raw_val, dict):
                    gps_ifd = raw_val
                else:
                    gps_ifd = dict(exif_data.get_ifd(tag_id))
            except Exception:
                pass
            continue   # handled separately below

        # Convert rational / bytes / tuples to clean python types
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

        # Truncate very long values
        if len(display) > 200:
            display = display[:197] + "…"

        sensitive = tag_name in _SENSITIVE_TAG_NAMES
        if sensitive:
            result["has_sensitive"] = True

        result["fields"].append({
            "tag":       tag_name,
            "value":     display,
            "sensitive": sensitive,
        })

    # ── GPS IFD ───────────────────────────────────────────────────────────────
    if gps_ifd:
        result["has_sensitive"] = True
        lat_val  = gps_ifd.get(2)   # GPSLatitude
        lat_ref  = gps_ifd.get(1, '')  # GPSLatitudeRef
        lon_val  = gps_ifd.get(4)   # GPSLongitude
        lon_ref  = gps_ifd.get(3, '')  # GPSLongitudeRef
        alt_val  = gps_ifd.get(6)   # GPSAltitude

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
            result["fields"].append({"tag": "GPS Latitude",  "value": f"{lat}°",  "sensitive": True})
            result["fields"].append({"tag": "GPS Longitude", "value": f"{lon}°",  "sensitive": True})
            if alt is not None:
                result["fields"].append({"tag": "GPS Altitude", "value": f"{alt} m", "sensitive": True})
        else:
            # Log raw GPS tags even if we couldn't parse coords
            for gps_tag_id, gps_raw in gps_ifd.items():
                gps_name = _GPS_TAG_MAP.get(gps_tag_id, f"GPS_{gps_tag_id}")
                try:
                    gps_display = str(gps_raw)
                except Exception:
                    gps_display = repr(gps_raw)
                result["fields"].append({"tag": gps_name, "value": gps_display[:200], "sensitive": True})

    # Sort: sensitive fields first
    result["fields"].sort(key=lambda f: (0 if f["sensitive"] else 1, f["tag"]))

    return result


# ── Public API ────────────────────────────────────────────────────────────────
def scan_image(raw_bytes: bytes) -> ScanResult:
    """
    Main entry point.
    Accepts raw image bytes; returns a ScanResult.
    Never writes to disk.
    """
    try:
        cv_img, pil_img = _load_image(raw_bytes)
    except ValueError as exc:
        return ScanResult(error=str(exc))

    all_detections: list[Detection] = []

    # ── EXIF extraction (before any downscaling side-effects) ─────────────────
    # Re-open original bytes to get EXIF before thumbnail resize strips metadata
    exif_data: dict = {}
    try:
        pil_orig = Image.open(io.BytesIO(raw_bytes))
        pil_orig.load()
        exif_data = _extract_exif(pil_orig)
    except Exception:
        exif_data = {"fields": [], "gps": {}, "has_sensitive": False}

    # ── OCR (one pass, reuse for phone + vreg) ────────────────────────────────
    ocr_result = _run_ocr(cv_img)
    all_detections.extend(_detect_phones(ocr_result))
    all_detections.extend(_detect_vregs(ocr_result))

    # ── QR ────────────────────────────────────────────────────────────────────
    all_detections.extend(_detect_qr(cv_img))

    # ── Faces ─────────────────────────────────────────────────────────────────
    all_detections.extend(_detect_faces(cv_img))

    # ── Risk + findings ───────────────────────────────────────────────────────
    risk, findings = _build_risk_and_findings(all_detections)

    # Bump risk if sensitive EXIF metadata was found
    if exif_data.get("has_sensitive"):
        if risk == "Low":
            risk = "Medium"
        # GPS data is especially serious
        if exif_data.get("gps"):
            if risk in ("Low", "Medium"):
                risk = "High"

    # ── Annotated image ───────────────────────────────────────────────────────
    try:
        annotated_b64 = _annotate(cv_img, all_detections)
    except Exception:
        annotated_b64 = ""

    return ScanResult(
        detections=all_detections,
        risk=risk,
        findings=findings,
        annotated_b64=annotated_b64,
        exif=exif_data,
    )


# ── Serialisation helper ──────────────────────────────────────────────────────
def scan_result_to_dict(result: ScanResult) -> dict:
    """Convert ScanResult to a JSON-serialisable dict."""
    if result.error:
        return {"error": result.error}

    return {
        "risk":      result.risk,
        "findings":  result.findings,
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
        "clean": len(result.detections) == 0,
        "exif": result.exif,
    }
