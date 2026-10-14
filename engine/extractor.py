# engine/extractor.py
"""
Nuclei-compatible Extractor Engine.
Extracts dynamic values (e.g. software versions, product names) from HTTP responses.
"""
from __future__ import annotations

import re
from typing import Any
from .matcher import ResponseContext


class Extractor:
    """
    Extracts structured values from HTTP responses based on Nuclei extractor definitions.

    YAML example:
      type: regex | kval
      name: version
      part: body | header | all | header.<name>
      group: 1
      regex: ["jquery[./-]([\\d.]+)"]
      kval: ["server", "x-powered-by"]
    """

    def __init__(self, config: dict[str, Any]):
        self.type = str(config.get("type", "regex")).strip().lower()
        self.name = str(config.get("name", "extracted"))
        self.part = str(config.get("part", "body")).strip().lower()
        self.group = int(config.get("group", 1))

        self.kvals: list[str] = [str(k) for k in config.get("kval", [])]
        raw_regexes = config.get("regex", [])
        self._compiled_regexes: list[re.Pattern] = []
        for pat in raw_regexes:
            try:
                self._compiled_regexes.append(re.compile(str(pat), re.IGNORECASE))
            except re.error:
                pass

    def _resolve_part(self, ctx: ResponseContext) -> str:
        part = self.part
        if part == "body":
            return ctx.body
        elif part in ("header", "headers"):
            return ctx.raw_headers
        elif part in ("all", "response"):
            return ctx.all_content
        elif part.startswith("header."):
            hdr_name = part.split(".", 1)[1]
            return ctx.get_header(hdr_name)
        elif part.startswith("header:"):
            hdr_name = part.split(":", 1)[1]
            return ctx.get_header(hdr_name)
        return ctx.body

    def extract(self, ctx: ResponseContext) -> list[str]:
        """Extract matching values from the designated response part."""
        results: list[str] = []

        if self.type == "regex":
            target_str = self._resolve_part(ctx)
            for reg in self._compiled_regexes:
                for match in reg.finditer(target_str):
                    try:
                        val = match.group(self.group)
                        if val:
                            val = val.strip().rstrip(".-_")
                        if val and val not in results:
                            results.append(val)
                    except IndexError:
                        # Fallback to full match if group not present
                        val = match.group(0)
                        if val:
                            val = val.strip().rstrip(".-_")
                        if val and val not in results:
                            results.append(val)

        elif self.type == "kval":
            for k in self.kvals:
                val = ctx.get_header(k)
                if val and val not in results:
                    results.append(val)

        return results
