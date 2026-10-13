# ocr_worker.py
"""
Isolated subprocess worker for RapidOCR.
Executes OCR in a separate OS process to insulate the main web server (uvicorn/FastAPI)
from native ONNX Runtime / OpenCV access violations, segmentation faults, or aborts.
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    try:
        raw_bytes = sys.stdin.buffer.read()
        if not raw_bytes:
            sys.stdout.write("[]")
            return

        import cv2
        import numpy as np
        from rapidocr_onnxruntime import RapidOCR

        nparr = np.frombuffer(raw_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            sys.stdout.write("[]")
            return

        engine = RapidOCR()
        res, _ = engine(img)

        output = []
        if res:
            for item in res:
                box = item[0]
                text = str(item[1])
                score = float(item[2]) if len(item) > 2 else 0.0
                output.append([box, text, score])

        sys.stdout.write(json.dumps(output))
    except Exception as exc:
        sys.stderr.write(f"OCR worker error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
