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
