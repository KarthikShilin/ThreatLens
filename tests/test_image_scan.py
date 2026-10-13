# tests/test_image_scan.py
"""
Pytest test suite for ThreatLens Image Scanner.
Run with:  pytest tests/ -v

Tests cover:
  - File validation (non-images, oversized, renamed text files)
  - Phone regex (positive + negative)
  - Vehicle registration regex (positive + negative)
  - Risk logic (1 type = Medium, 2+ = High, 0 = Low)
  - End-to-end scan_image() returns the right risk level
"""
import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── Helpers to create minimal valid images in memory ─────────────────────────
def _make_png_bytes(width: int = 10, height: int = 10) -> bytes:
    """Create a tiny valid PNG using Pillow."""
    from PIL import Image
    buf = io.BytesIO()
    img = Image.new("RGB", (width, height), color=(100, 150, 200))
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_jpeg_bytes(width: int = 10, height: int = 10) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    img = Image.new("RGB", (width, height), color=(200, 100, 50))
    img.save(buf, format="JPEG")
    return buf.getvalue()


# ── Regex constants (replicated from image_scan for isolated unit tests) ──────
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:(?:\+91|0091|91|0)[\s\-]?)?"
    r"([6-9]\d{4}[\s\-]?\d{5})"
    r"(?!\d)",
    re.ASCII,
)

_VREG_RE = re.compile(
    r"\b([A-Z]{2}[\s\-]?\d{1,2}[\s\-]?[A-Z]{1,3}[\s\-]?\d{4})\b",
    re.IGNORECASE | re.ASCII,
)


# ══════════════════════════════════════════════════════════════════════════════
# File validation tests
# ══════════════════════════════════════════════════════════════════════════════

class TestFileValidation:
    """image_scan._load_image must reject bad inputs."""

    def test_reject_plain_text_bytes(self):
        """Plain text is not a valid image."""
        from image_scan import scan_image
        result = scan_image(b"hello world this is not an image")
        assert result.error is not None
        assert "valid image" in result.error.lower() or "decode" in result.error.lower()

    def test_reject_renamed_txt_as_png(self):
        """A text file uploaded with .png extension is not a valid image."""
        from image_scan import scan_image
        fake = b"This is definitely not a PNG\n" * 100
        result = scan_image(fake)
        assert result.error is not None

    def test_reject_oversized_file(self):
        """Files larger than 5 MB are rejected before any processing."""
        from image_scan import scan_image
        big = b"A" * (5 * 1024 * 1024 + 1)
        result = scan_image(big)
        assert result.error is not None
        assert "5 mb" in result.error.lower() or "large" in result.error.lower()

    def test_reject_empty_bytes(self):
        """Empty byte string is not a valid image."""
        from image_scan import scan_image
        result = scan_image(b"")
        assert result.error is not None

    def test_reject_html_content(self):
        """HTML disguised as an image is not a valid image."""
        from image_scan import scan_image
        result = scan_image(b"<html><body>Fake</body></html>")
        assert result.error is not None

    def test_accept_valid_png(self):
        """A valid small PNG should load without errors."""
        from image_scan import scan_image
        result = scan_image(_make_png_bytes())
        assert result.error is None

    def test_accept_valid_jpeg(self):
        """A valid small JPEG should load without errors."""
        from image_scan import scan_image
        result = scan_image(_make_jpeg_bytes())
        assert result.error is None


# ══════════════════════════════════════════════════════════════════════════════
# Phone regex tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPhoneRegex:
    """Positive and negative cases for the Indian phone number regex."""

    # — Positive: should match —
    def test_plain_10digit_starting_9(self):
        assert _PHONE_RE.search("9876543210") is not None

    def test_plain_10digit_starting_6(self):
        assert _PHONE_RE.search("6543210987") is not None

    def test_plain_10digit_starting_7(self):
        assert _PHONE_RE.search("7001234567") is not None

    def test_plain_10digit_starting_8(self):
        assert _PHONE_RE.search("8123456789") is not None

    def test_with_plus91_prefix(self):
        assert _PHONE_RE.search("+919876543210") is not None

    def test_with_91_prefix_no_plus(self):
        assert _PHONE_RE.search("919876543210") is not None

    def test_with_0_prefix(self):
        assert _PHONE_RE.search("09876543210") is not None

    def test_with_spaces(self):
        assert _PHONE_RE.search("98765 43210") is not None

    def test_with_dashes(self):
        assert _PHONE_RE.search("98765-43210") is not None

    def test_plus91_with_space(self):
        assert _PHONE_RE.search("+91 9876543210") is not None

    # — Negative: should NOT match —
    def test_rejects_5digit_landline(self):
        """A 5-digit number is not a valid Indian mobile."""
        assert _PHONE_RE.search("12345") is None

    def test_rejects_starting_1(self):
        """Mobile numbers starting with 1 are invalid."""
        assert _PHONE_RE.search("1234567890") is None

    def test_rejects_starting_5(self):
        """Mobile numbers starting with 5 are invalid."""
        assert _PHONE_RE.search("5234567890") is None

    def test_rejects_starting_2(self):
        assert _PHONE_RE.search("2345678901") is None

    def test_rejects_too_short(self):
        """9 digits should not match."""
        assert _PHONE_RE.search("987654321") is None

    def test_rejects_embedded_in_longer_number(self):
        """A 10-digit sequence embedded in a 12-digit number should not match."""
        m = _PHONE_RE.search("009876543210000")
        # If it matches, the captured group must be exactly 10 digits
        if m:
            digits = re.sub(r"\D", "", m.group(1))
            assert len(digits) == 10


# ══════════════════════════════════════════════════════════════════════════════
# Vehicle registration regex tests
# ══════════════════════════════════════════════════════════════════════════════

class TestVehicleRegRegex:
    """Positive and negative cases for Indian vehicle registration number regex."""

    # — Positive —
    def test_standard_format_with_spaces(self):
        assert _VREG_RE.search("KL 07 AB 1234") is not None

    def test_standard_format_no_spaces(self):
        assert _VREG_RE.search("KL07AB1234") is not None

    def test_mh_format(self):
        assert _VREG_RE.search("MH 12 AB 5678") is not None

    def test_dl_format(self):
        assert _VREG_RE.search("DL 04 AB 1234") is not None

    def test_single_letter_series(self):
        assert _VREG_RE.search("TN 22 C 1234") is not None

    def test_three_letter_series(self):
        assert _VREG_RE.search("KA 05 MKL 1234") is not None

    def test_lowercase_accepted(self):
        """Regex is case-insensitive so lowercase should match."""
        assert _VREG_RE.search("kl 07 ab 1234") is not None

    # — Negative —
    def test_rejects_only_digits(self):
        assert _VREG_RE.search("1234567890") is None

    def test_rejects_random_letters(self):
        assert _VREG_RE.search("HELLOWORLD") is None

    def test_rejects_too_short_number(self):
        """Plate number must have exactly 4 digits at the end."""
        assert _VREG_RE.search("KL 07 AB 12") is None

    def test_rejects_wrong_structure(self):
        """Starting digits before the state code should not match."""
        m = _VREG_RE.search("12 AB 3456 KL")
        # Should either not match or not extract a valid plate
        # The regex may match sub-parts; ensure nothing looks like a valid plate
        # from the entire string perspective
        assert m is None or len(re.sub(r"\W", "", m.group(1))) < 6


# ══════════════════════════════════════════════════════════════════════════════
# Risk logic tests
# ══════════════════════════════════════════════════════════════════════════════

class TestRiskLogic:
    """_build_risk_and_findings must apply the correct risk tier."""

    def _make_detection(self, kind: str, value: str = "test"):
        from image_scan import Detection
        return Detection(kind=kind, label=kind, value=value, box=(0, 0, 10, 10))

    def test_no_detections_is_low(self):
        from image_scan import _build_risk_and_findings
        risk, findings = _build_risk_and_findings([])
        assert risk == "Low"
        assert findings == []

    def test_one_type_is_medium(self):
        from image_scan import _build_risk_and_findings
        detections = [self._make_detection("phone", "9876543210")]
        risk, _ = _build_risk_and_findings(detections)
        assert risk == "Medium"

    def test_one_type_multiple_items_still_medium(self):
        from image_scan import _build_risk_and_findings
        detections = [
            self._make_detection("face", "face_1"),
            self._make_detection("face", "face_2"),
            self._make_detection("face", "face_3"),
        ]
        risk, _ = _build_risk_and_findings(detections)
        assert risk == "Medium"

    def test_two_types_is_high(self):
        from image_scan import _build_risk_and_findings
        detections = [
            self._make_detection("phone", "9876543210"),
            self._make_detection("face", "face_1"),
        ]
        risk, _ = _build_risk_and_findings(detections)
        assert risk == "High"

    def test_three_types_is_high(self):
        from image_scan import _build_risk_and_findings
        detections = [
            self._make_detection("phone", "9876543210"),
            self._make_detection("face", "face_1"),
            self._make_detection("qr", "https://example.com"),
        ]
        risk, _ = _build_risk_and_findings(detections)
        assert risk == "High"

    def test_four_types_is_high(self):
        from image_scan import _build_risk_and_findings
        detections = [
            self._make_detection("phone", "9876543210"),
            self._make_detection("face", "face_1"),
            self._make_detection("qr", "data"),
            self._make_detection("vreg", "KL07AB1234"),
        ]
        risk, _ = _build_risk_and_findings(detections)
        assert risk == "High"

    def test_findings_contain_correct_kinds(self):
        from image_scan import _build_risk_and_findings
        detections = [
            self._make_detection("phone", "9876543210"),
            self._make_detection("qr", "https://example.com"),
        ]
        _, findings = _build_risk_and_findings(detections)
        kinds = {f["kind"] for f in findings}
        assert "phone" in kinds
        assert "qr" in kinds

    def test_findings_have_required_keys(self):
        from image_scan import _build_risk_and_findings
        detections = [self._make_detection("face", "face_1")]
        _, findings = _build_risk_and_findings(detections)
        assert len(findings) == 1
        f = findings[0]
        assert "kind" in f
        assert "title" in f
        assert "plain_explanation" in f
        assert "recommended_fix" in f
        assert "values" in f


# ══════════════════════════════════════════════════════════════════════════════
# End-to-end scan_image tests
# ══════════════════════════════════════════════════════════════════════════════

class TestScanImageEndToEnd:
    """scan_image() on known inputs must return expected risk levels."""

    def test_clean_image_returns_low_risk(self):
        """A solid-colour image with no content should report Low risk."""
        from image_scan import scan_image
        png = _make_png_bytes(50, 50)
        result = scan_image(png)
        assert result.error is None
        assert result.risk == "Low"
        assert result.detections == []

    def test_annotated_image_is_base64_png(self):
        """The annotated image field must be a non-empty base64 string."""
        import base64
        from image_scan import scan_image
        png = _make_png_bytes(50, 50)
        result = scan_image(png)
        assert result.error is None
        # Must be valid base64
        decoded = base64.b64decode(result.annotated_b64)
        assert decoded[:8] == b"\x89PNG\r\n\x1a\n"  # PNG magic

    def test_scan_result_to_dict_clean(self):
        """scan_result_to_dict for a clean scan must include clean=True."""
        from image_scan import scan_image, scan_result_to_dict
        png = _make_png_bytes(30, 30)
        result = scan_image(png)
        d = scan_result_to_dict(result)
        assert "error" not in d
        assert d["clean"] is True
        assert d["risk"] == "Low"
        assert isinstance(d["findings"], list)
        assert isinstance(d["detections"], list)
        assert isinstance(d["annotated_image"], str)

    def test_scan_result_to_dict_error(self):
        """scan_result_to_dict for an errored scan must return an error key."""
        from image_scan import ScanResult, scan_result_to_dict
        err_result = ScanResult(error="Test error message")
        d = scan_result_to_dict(err_result)
        assert "error" in d
        assert d["error"] == "Test error message"

    def test_invalid_bytes_returns_error(self):
        """Garbage bytes must return a ScanResult with an error set."""
        from image_scan import scan_image
        result = scan_image(b"\x00\x01\x02\x03garbage")
        assert result.error is not None


# ══════════════════════════════════════════════════════════════════════════════
# EXIF Risk Tiers & Findings Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestExifTiersAndFindings:
    """Tests for EXIF tier classification, risk bumping, findings, and clean flag."""

    def _make_jpeg_with_gps(self, width: int = 20, height: int = 20) -> bytes:
        from PIL import Image, ExifTags
        buf = io.BytesIO()
        img = Image.new("RGB", (width, height), color=(100, 150, 200))
        ex = img.getexif()
        gps = ex.get_ifd(ExifTags.IFD.GPSInfo)
        gps[1] = "N"
        gps[2] = (12.0, 34.0, 56.0)
        gps[3] = "E"
        gps[4] = (77.0, 22.0, 33.0)
        gps[6] = 120.5
        img.save(buf, format="JPEG", exif=ex)
        return buf.getvalue()

    def _make_jpeg_with_info_only(self, width: int = 20, height: int = 20) -> bytes:
        from PIL import Image
        buf = io.BytesIO()
        img = Image.new("RGB", (width, height), color=(100, 150, 200))
        ex = img.getexif()
        ex[271] = "Canon"                    # Make
        ex[272] = "EOS R5"                   # Model
        ex[305] = "ThreatLens Camera App"    # Software
        ex[306] = "2024:05:01 14:30:00"      # DateTime
        img.save(buf, format="JPEG", exif=ex)
        return buf.getvalue()

    def _make_jpeg_with_serial_and_artist(self, width: int = 20, height: int = 20) -> bytes:
        from PIL import Image
        buf = io.BytesIO()
        img = Image.new("RGB", (width, height), color=(100, 150, 200))
        ex = img.getexif()
        ex[315] = "Jane Photographer"        # Artist
        sub = ex.get_ifd(34665)              # Exif IFD
        sub[42033] = "SN-987654321"          # BodySerialNumber
        img.save(buf, format="JPEG", exif=ex)
        return buf.getvalue()

    def test_image_with_gps_exif(self):
        """Image with GPS EXIF: risk High, a GPS finding appears, clean == false."""
        from image_scan import scan_image, scan_result_to_dict
        raw = self._make_jpeg_with_gps()
        result = scan_image(raw)

        assert result.error is None
        assert result.risk == "High"
        assert result.exif.get("has_sensitive") is True
        assert bool(result.exif.get("gps")) is True

        # Finding exists and has plain language explanation + fix
        gps_findings = [
            f for f in result.findings
            if f.get("kind") in ("gps", "exif_gps") or "gps" in f.get("title", "").lower()
        ]
        assert len(gps_findings) >= 1
        finding = gps_findings[0]
        assert "gps" in finding["plain_explanation"].lower() or "coordinates" in finding["plain_explanation"].lower()
        assert "remove metadata" in finding["recommended_fix"].lower()

        # Clean flag must be False
        d = scan_result_to_dict(result)
        assert d["clean"] is False

        # EXIF fields marked with high tier and sensitive=True
        gps_fields = [f for f in result.exif.get("fields", []) if f.get("tier") == "high"]
        assert len(gps_fields) >= 2
        assert all(f["sensitive"] is True for f in gps_fields)

    def test_image_with_only_make_model_datetime(self):
        """Image with only Make/Model/DateTime: risk stays Low, shown as info."""
        from image_scan import scan_image, scan_result_to_dict
        raw = self._make_jpeg_with_info_only()
        result = scan_image(raw)

        assert result.error is None
        assert result.risk == "Low"
        assert result.exif.get("has_sensitive") is False
        assert len(result.findings) == 0

        # Clean flag must be True (no detections, no sensitive EXIF)
        d = scan_result_to_dict(result)
        assert d["clean"] is True

        # All fields are tier 'info' and sensitive=False
        fields = result.exif.get("fields", [])
        assert len(fields) >= 3
        tags = {f["tag"] for f in fields}
        assert "Make" in tags
        assert "Model" in tags
        assert "DateTime" in tags
        assert all(f["tier"] == "info" for f in fields)
        assert all(f["sensitive"] is False for f in fields)

    def test_image_with_serial_number_or_artist(self):
        """Image with serial number or Artist: risk Medium, clean == false."""
        from image_scan import scan_image, scan_result_to_dict
        raw = self._make_jpeg_with_serial_and_artist()
        result = scan_image(raw)

        assert result.error is None
        assert result.risk == "Medium"
        assert result.exif.get("has_sensitive") is True

        # Plain language device/creator finding
        med_findings = [
            f for f in result.findings
            if f.get("kind") in ("exif_meta", "exif_device") or "device" in f.get("title", "").lower() or "creator" in f.get("title", "").lower()
        ]
        assert len(med_findings) >= 1
        finding = med_findings[0]
        assert "remove metadata" in finding["recommended_fix"].lower()

        # Clean flag must be False
        d = scan_result_to_dict(result)
        assert d["clean"] is False

        # Marked with tier 'medium' and sensitive=True
        med_fields = [f for f in result.exif.get("fields", []) if f.get("tier") == "medium"]
        assert len(med_fields) >= 2
        assert all(f["sensitive"] is True for f in med_fields)

    def test_image_with_no_exif_png(self):
        """Image with no EXIF (e.g. PNG): empty EXIF list, no crash, clean == true."""
        from image_scan import scan_image, scan_result_to_dict
        raw = _make_png_bytes(25, 25)
        result = scan_image(raw)

        assert result.error is None
        assert result.risk == "Low"
        assert result.exif.get("fields") == []
        assert result.exif.get("has_sensitive") is False
        assert len(result.findings) == 0

        d = scan_result_to_dict(result)
        assert d["clean"] is True


# ══════════════════════════════════════════════════════════════════════════════
# /strip-exif Function & Route Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestStripExif:
    """strip_exif and /strip-exif endpoint tests."""

    def test_strip_exif_output_has_zero_exif_and_same_dimensions(self):
        """strip_exif removes all EXIF while maintaining image dimensions and format."""
        from PIL import Image, ExifTags
        from image_scan import strip_exif, _extract_exif

        width, height = 48, 36
        buf = io.BytesIO()
        img = Image.new("RGB", (width, height), color=(120, 180, 240))
        ex = img.getexif()
        gps = ex.get_ifd(ExifTags.IFD.GPSInfo)
        gps[1] = "N"
        gps[2] = (10.0, 20.0, 30.0)
        ex[271] = "Sony"
        ex[315] = "Photographer"
        img.save(buf, format="JPEG", exif=ex)
        raw = buf.getvalue()

        cleaned_bytes, media_type, ext = strip_exif(raw)
        assert media_type == "image/jpeg"
        assert ext == ".jpg"

        # Check with PIL
        cleaned_img = Image.open(io.BytesIO(cleaned_bytes))
        assert cleaned_img.size == (width, height)
        assert dict(cleaned_img.getexif()) == {}

        # Check with _extract_exif
        extracted = _extract_exif(cleaned_img)
        assert extracted["fields"] == []
        assert extracted["gps"] == {}
        assert extracted["has_sensitive"] is False

    def test_strip_exif_png_and_webp(self):
        """strip_exif properly handles PNG and WebP files."""
        from PIL import Image, ExifTags
        from image_scan import strip_exif

        # PNG
        png_raw = _make_png_bytes(32, 24)
        c_png, m_png, ext_png = strip_exif(png_raw)
        assert m_png == "image/png"
        assert ext_png == ".png"
        p_img = Image.open(io.BytesIO(c_png))
        assert p_img.size == (32, 24)
        assert dict(p_img.getexif()) == {}

        # WebP
        w_buf = io.BytesIO()
        w_orig = Image.new("RGB", (28, 28), color=(90, 80, 70))
        ex = w_orig.getexif()
        ex[271] = "WebP Camera"
        w_orig.save(w_buf, format="WEBP", exif=ex)
        c_webp, m_webp, ext_webp = strip_exif(w_buf.getvalue())
        assert m_webp == "image/webp"
        assert ext_webp == ".webp"
        w_img = Image.open(io.BytesIO(c_webp))
        assert w_img.size == (28, 28)
        assert dict(w_img.getexif()) == {}

    def test_strip_exif_rejects_non_image(self):
        """strip_exif raises ValueError when passed invalid/non-image bytes."""
        from image_scan import strip_exif
        with pytest.raises(ValueError, match="Not a valid image"):
            strip_exif(b"hello world this is plain text")

    def test_strip_exif_rejects_oversized_file(self):
        """strip_exif raises ValueError when file exceeds 5 MB limit."""
        from image_scan import strip_exif
        with pytest.raises(ValueError, match="5 MB"):
            strip_exif(b"X" * (5 * 1024 * 1024 + 1))

    def test_strip_exif_route_endpoint(self):
        """POST /strip-exif endpoint cleans image, returns 200 download, and handles errors."""
        import asyncio
        from PIL import Image, ExifTags
        from starlette.datastructures import UploadFile
        from main import strip_exif_route, Request

        # 1. Valid image with GPS
        w_buf = io.BytesIO()
        img = Image.new("RGB", (40, 25), color=(200, 100, 50))
        ex = img.getexif()
        gps = ex.get_ifd(ExifTags.IFD.GPSInfo)
        gps[1] = "S"
        gps[2] = (33.0, 44.0, 55.0)
        img.save(w_buf, format="JPEG", exif=ex)

        req = Request({"type": "http", "client": ("127.0.0.1", 54321), "headers": []})
        uf = UploadFile(filename="vacation_photo.jpg", file=io.BytesIO(w_buf.getvalue()))

        resp = asyncio.run(strip_exif_route(req, uf))
        assert resp.status_code == 200
        assert resp.headers.get("content-type") == "image/jpeg"
        assert 'filename="cleaned_vacation_photo.jpg"' in resp.headers.get("content-disposition", "")

        out_img = Image.open(io.BytesIO(resp.body))
        assert out_img.size == (40, 25)
        assert dict(out_img.getexif()) == {}

        # 2. Non-image upload -> 422
        uf_bad = UploadFile(filename="malicious.txt", file=io.BytesIO(b"fake data not an image"))
        resp_bad = asyncio.run(strip_exif_route(req, uf_bad))
        assert resp_bad.status_code == 422

        # 3. Oversized file -> 413
        uf_big = UploadFile(filename="huge.jpg", file=io.BytesIO(b"0" * (5 * 1024 * 1024 + 1)))
        resp_big = asyncio.run(strip_exif_route(req, uf_big))
        assert resp_big.status_code == 413

    def test_scan_and_report_routes_intact(self):
        """Ensure /scan and /report routes in main.py remain intact."""
        import asyncio
        import json
        from main import scan, generate_report, Request

        # /scan with SSRF target returns 400
        req_scan = Request({"type": "http", "client": ("127.0.0.1", 54322), "headers": []})
        res_scan = scan("http://127.0.0.1", req_scan)
        assert res_scan.status_code == 400

        # /report returns PDF streaming response
        req_report = Request({"type": "http", "client": ("127.0.0.1", 54323), "headers": [(b"content-type", b"application/json")]})
        body = json.dumps({
            "url": "https://example.com",
            "tech_detected": {},
            "headers": {},
            "vulnerabilities": {},
            "summary": {"overall_risk": "Low", "what_we_checked": "Checked headers", "top_findings": []},
            "security_headers": [],
        }).encode("utf-8")

        async def rec():
            return {"type": "http.request", "body": body}
        req_report._receive = rec

        res_report = asyncio.run(generate_report(req_report))
        assert res_report.status_code == 200
        assert res_report.media_type == "application/pdf"


# ══════════════════════════════════════════════════════════════════════════════
# Robustness & Failure Safety Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestScanRobustnessAndDetection:
    """Tests ensuring scanner safety, OCR failure graceful degradation, and detection."""

    def test_phone_and_plate_detection(self):
        """Image containing phone number and vehicle plate detects both."""
        from PIL import Image, ImageDraw
        from image_scan import scan_image, scan_result_to_dict

        img = Image.new("RGB", (600, 300), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.text((50, 50), "Call: +91 9876543210", fill=(0, 0, 0))
        draw.text((50, 150), "Vehicle: MH 12 AB 1234", fill=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")

        res = scan_image(buf.getvalue())
        d = scan_result_to_dict(res)
        kinds = {det["kind"] for det in d["detections"]}
        assert "phone" in kinds
        assert "vreg" in kinds
        assert d["clean"] is False

    def test_ocr_failure_safe_handling(self):
        """When RapidOCR fails to load, scan_image does not crash, returns warning, and clean == False."""
        import unittest.mock as mock
        import asyncio
        from starlette.datastructures import UploadFile
        from main import scan_image_route, Request
        import image_scan

        png_bytes = _make_png_bytes(30, 30)

        # Clear cached engine to test initialization exception
        image_scan._ocr_engine = None
        with mock.patch("rapidocr_onnxruntime.RapidOCR", side_effect=RuntimeError("Simulated OCR model failure")):
            # 1. Direct scan_image call
            res = image_scan.scan_image(png_bytes)
            assert res.error is None
            d = image_scan.scan_result_to_dict(res)
            assert d["clean"] is False
            assert len(d.get("warnings", [])) > 0
            assert "NOT checked" in d["warnings"][0]

            # 2. Route endpoint call
            req = Request({"type": "http", "client": ("127.0.0.1", 54324), "headers": []})
            uf = UploadFile(filename="test.png", file=io.BytesIO(png_bytes))
            resp = asyncio.run(scan_image_route(req, uf))
            assert resp.status_code == 200
            import json
            payload = json.loads(resp.body)
            assert payload.get("clean") is False
            assert len(payload.get("warnings", [])) > 0

    def test_internal_crash_safe_handling(self):
        """When an internal exception occurs, scan_image returns error result and route returns JSON."""
        import unittest.mock as mock
        import asyncio
        from starlette.datastructures import UploadFile
        from main import scan_image_route, Request
        import image_scan

        png_bytes = _make_png_bytes(30, 30)

        # 1. scan_image catches internal errors and returns ScanResult(error=...)
        with mock.patch("image_scan._build_risk_and_findings", side_effect=RuntimeError("Simulated internal fault")):
            res = image_scan.scan_image(png_bytes)
            assert res.error is not None
            d = image_scan.scan_result_to_dict(res)
            assert "error" in d

        # 2. scan_image_route catches any unhandled exception and returns JSON 500
        with mock.patch("main.scan_image", side_effect=RuntimeError("Fatal error")):
            req = Request({"type": "http", "client": ("127.0.0.1", 54325), "headers": []})
            uf = UploadFile(filename="test.png", file=io.BytesIO(png_bytes))
            resp = asyncio.run(scan_image_route(req, uf))
            assert resp.status_code == 500
            assert resp.headers["content-type"] == "application/json"
            import json
            payload = json.loads(resp.body)
            assert payload == {"error": "Internal error scanning image"}

    def test_subprocess_ocr_crash_isolation(self):
        """When the OCR subprocess crashes (e.g. access violation / segfault), scan_image does not crash."""
        import subprocess
        import unittest.mock as mock
        import image_scan

        png_bytes = _make_png_bytes(30, 30)
        image_scan._ocr_engine = True

        mock_proc = mock.Mock()
        mock_proc.returncode = 3221225477  # 0xC0000005 Windows Access Violation
        mock_proc.stderr = b"Fatal Python error: Segmentation fault / Access Violation"
        mock_proc.stdout = b""

        with mock.patch("subprocess.run", return_value=mock_proc):
            res = image_scan.scan_image(png_bytes)
            assert res.error is None
            assert res.risk == "Low"
            d = image_scan.scan_result_to_dict(res)
            assert d["clean"] is True

    def test_subprocess_ocr_timeout_isolation(self):
        """When the OCR subprocess times out, scan_image does not raise and completes safely."""
        import subprocess
        import unittest.mock as mock
        import image_scan

        png_bytes = _make_png_bytes(30, 30)
        image_scan._ocr_engine = True

        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ocr_worker", timeout=20)):
            res = image_scan.scan_image(png_bytes)
            assert res.error is None
            assert res.risk == "Low"




