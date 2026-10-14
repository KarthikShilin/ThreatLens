# engine/template.py
"""
Nuclei Template parser and evaluator.
Loads declarative YAML templates and executes matchers and extractors.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any
import yaml

from .matcher import Matcher, ResponseContext
from .extractor import Extractor


@dataclass
class TemplateMatchResult:
    """Result returned when a template matches a target response."""
    template_id: str
    name: str
    tech: str
    severity: str
    description: str
    category: str = "technologies"
    tags: list[str] = field(default_factory=list)
    matched_at: str = ""
    cpe: str | None = None
    extracted: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def detected_version(self) -> str:
        """Helper to return the primary extracted version or 'detected'."""
        versions = self.extracted.get("version", [])
        if versions:
            return versions[0]
        return "detected"


class Template:
    """Represents a parsed Nuclei YAML template."""

    def __init__(self, raw: dict[str, Any], filepath: str = ""):
        self.raw = raw
        self.filepath = filepath
        self.id = str(raw.get("id", os.path.splitext(os.path.basename(filepath))[0] if filepath else "unknown"))

        info = raw.get("info", {})
        self.name = str(info.get("name", self.id))
        self.author = str(info.get("author", "ThreatLens"))
        self.severity = str(info.get("severity", "info")).upper()
        self.description = str(info.get("description", ""))
        self.metadata = info.get("metadata", {}) or {}

        # Tags and Category
        tags_raw = info.get("tags", [])
        if isinstance(tags_raw, str):
            self.tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        else:
            self.tags = [str(t) for t in tags_raw]

        dir_category = os.path.basename(os.path.dirname(filepath)) if filepath else "technologies"
        self.category = str(self.metadata.get("category", dir_category))

        # Tech name (defaults to name or metadata.tech)
        self.tech = str(self.metadata.get("tech", self.name))
        self.cpe = self.metadata.get("cpe")

        # Requests / HTTP section
        # Nuclei supports both 'requests' and 'http' keys
        req_blocks = raw.get("http", raw.get("requests", []))
        if isinstance(req_blocks, dict):
            req_blocks = [req_blocks]

        self.matchers: list[Matcher] = []
        self.extractors: list[Extractor] = []
        self.paths: list[str] = ["{{BaseURL}}"]
        self.method: str = "GET"
        self.matchers_condition = "or"

        if req_blocks:
            primary_req = req_blocks[0]
            self.method = str(primary_req.get("method", "GET")).upper()
            raw_paths = primary_req.get("path", ["{{BaseURL}}"])
            if isinstance(raw_paths, str):
                raw_paths = [raw_paths]
            self.paths = [str(p) for p in raw_paths]

            self.matchers_condition = str(
                primary_req.get("matchers-condition", primary_req.get("matchers_condition", "or"))
            ).lower()

            for m in primary_req.get("matchers", []):
                self.matchers.append(Matcher(m))

            for e in primary_req.get("extractors", []):
                self.extractors.append(Extractor(e))

        # Top-level matchers fallback
        if not self.matchers and "matchers" in raw:
            self.matchers_condition = str(raw.get("matchers-condition", "or")).lower()
            for m in raw.get("matchers", []):
                self.matchers.append(Matcher(m))

    @classmethod
    def from_yaml_file(cls, path: str) -> Template:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(data or {}, filepath=path)

    def execute(self, ctx: ResponseContext, matched_at: str = "") -> TemplateMatchResult | None:
        """
        Evaluate template matchers against the given response.
        If matched, run extractors and return TemplateMatchResult.
        """
        if not self.matchers:
            return None

        evaluations = [matcher.matches(ctx) for matcher in self.matchers]

        matched = all(evaluations) if self.matchers_condition == "and" else any(evaluations)
        if not matched:
            return None

        # Run extractors
        extracted_data: dict[str, list[str]] = {}
        for extractor in self.extractors:
            vals = extractor.extract(ctx)
            if vals:
                extracted_data.setdefault(extractor.name, []).extend(vals)

        return TemplateMatchResult(
            template_id=self.id,
            name=self.name,
            tech=self.tech,
            severity=self.severity,
            description=self.description,
            category=self.category,
            tags=self.tags,
            matched_at=matched_at,
            cpe=self.cpe,
            extracted=extracted_data,
            metadata=self.metadata,
        )
