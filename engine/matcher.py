# engine/matcher.py
"""
Nuclei-compatible Matcher Engine.
Supports word, regex, status, and DSL matching across HTTP response components.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass
class ResponseContext:
    """Standardized HTTP response container for matcher evaluation."""
    status_code: int
    headers: Mapping[str, str]
    body: str

    @property
    def raw_headers(self) -> str:
        return "\r\n".join(f"{k}: {v}" for k, v in self.headers.items())

    @property
    def all_content(self) -> str:
        return f"{self.raw_headers}\r\n\r\n{self.body}"

    def get_header(self, name: str) -> str:
        name_lower = name.strip().lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return ""


class Matcher:
    """
    Evaluates Nuclei-style matcher conditions against an HTTP response.
    
    YAML example:
      type: word | regex | status | dsl
      part: body | header | all | status | header.<name>
      words: ["WordPress", "wp-content"]
      regex: ["jquery[./-]([\\d.]+)"]
      status: [200, 301]
      condition: and | or (default: or)
      negative: true | false (default: false)
      case_insensitive: true | false (default: true)
    """

    def __init__(self, config: dict[str, Any]):
        self.type = str(config.get("type", "word")).strip().lower()
        self.part = str(config.get("part", "body")).strip().lower()
        self.condition = str(config.get("condition", "or")).strip().lower()
        self.negative = bool(config.get("negative", False))
        self.case_insensitive = bool(config.get("case-insensitive", config.get("case_insensitive", True)))

        self.words: list[str] = [str(w) for w in config.get("words", [])]
        self.status_codes: set[int] = {int(s) for s in config.get("status", [])}
        self.dsl_expressions: list[str] = [str(d) for d in config.get("dsl", [])]

        raw_regexes = config.get("regex", [])
        self.regex_patterns = [str(r) for r in raw_regexes]
        re_flags = re.IGNORECASE if self.case_insensitive else 0
        self._compiled_regexes: list[re.Pattern] = []
        for pat in self.regex_patterns:
            try:
                self._compiled_regexes.append(re.compile(pat, re_flags))
            except re.error:
                # If regex fails to compile, skip or log gracefully
                pass

    def _resolve_part(self, ctx: ResponseContext) -> str:
        """Extract the designated string content from the response context."""
        part = self.part
        if part == "body":
            return ctx.body
        elif part in ("header", "headers"):
            return ctx.raw_headers
        elif part in ("all", "response"):
            return ctx.all_content
        elif part == "status":
            return str(ctx.status_code)
        elif part.startswith("header."):
            hdr_name = part.split(".", 1)[1]
            return ctx.get_header(hdr_name)
        elif part.startswith("header:"):
            hdr_name = part.split(":", 1)[1]
            return ctx.get_header(hdr_name)
        return ctx.body

    def _match_words(self, target_str: str) -> bool:
        if not self.words:
            return False

        search_str = target_str.lower() if self.case_insensitive else target_str
        results = []
        for word in self.words:
            w = word.lower() if self.case_insensitive else word
            results.append(w in search_str)

        if self.condition == "and":
            return all(results)
        return any(results)

    def _match_regex(self, target_str: str) -> bool:
        if not self._compiled_regexes:
            return False

        results = [bool(reg.search(target_str)) for reg in self._compiled_regexes]
        if self.condition == "and":
            return all(results)
        return any(results)

    def _match_status(self, status_code: int) -> bool:
        if not self.status_codes:
            return False
        return status_code in self.status_codes

    def _match_dsl(self, ctx: ResponseContext) -> bool:
        if not self.dsl_expressions:
            return False

        # Safe DSL environment helper
        def contains(haystack: str, needle: str) -> bool:
            return needle.lower() in haystack.lower()

        safe_env = {
            "status_code": ctx.status_code,
            "body": ctx.body,
            "header": ctx.raw_headers,
            "contains": contains,
            "len": len,
            "to_lower": lambda s: str(s).lower(),
        }

        results = []
        for expr in self.dsl_expressions:
            try:
                # Evaluates simple boolean statements safely
                res = bool(eval(expr, {"__builtins__": {}}, safe_env))
                results.append(res)
            except Exception:
                results.append(False)

        if self.condition == "and":
            return all(results)
        return any(results)

    def matches(self, ctx: ResponseContext) -> bool:
        """Evaluate matcher against the response context, respecting negative flag."""
        matched = False

        if self.type == "word":
            matched = self._match_words(self._resolve_part(ctx))
        elif self.type == "regex":
            matched = self._match_regex(self._resolve_part(ctx))
        elif self.type == "status":
            matched = self._match_status(ctx.status_code)
        elif self.type == "dsl":
            matched = self._match_dsl(ctx)
        else:
            # Fallback to word matching if type is unspecified
            matched = self._match_words(self._resolve_part(ctx))

        if self.negative:
            return not matched
        return matched
