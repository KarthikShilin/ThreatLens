# engine/runner.py
"""
Nuclei-compatible Scan Runner.
Loads template registries and scans HTTP responses using template-driven algorithms.
"""
from __future__ import annotations

import os
import glob
from typing import Mapping, Sequence
import requests

from .matcher import ResponseContext
from .template import Template, TemplateMatchResult


class NucleiEngine:
    """
    Core engine managing Nuclei-compatible templates and executing them
    against target responses.
    """

    def __init__(self, template_dirs: Sequence[str] | None = None):
        self.template_dirs = list(template_dirs or [])
        self.templates: list[Template] = []
        self._loaded = False

    def load_templates(self) -> None:
        """Scan template directories and load all .yaml and .yml files."""
        self.templates.clear()
        for d in self.template_dirs:
            if not os.path.exists(d):
                continue
            pattern = os.path.join(d, "**", "*.yaml")
            for path in glob.glob(pattern, recursive=True):
                try:
                    tpl = Template.from_yaml_file(path)
                    self.templates.append(tpl)
                except Exception:
                    pass

            pattern_yml = os.path.join(d, "**", "*.yml")
            for path in glob.glob(pattern_yml, recursive=True):
                try:
                    tpl = Template.from_yaml_file(path)
                    self.templates.append(tpl)
                except Exception:
                    pass

        self._loaded = True

    def add_template(self, template: Template) -> None:
        self.templates.append(template)

    def scan_response(
        self,
        status_code: int,
        headers: Mapping[str, str],
        body: str,
    ) -> list[TemplateMatchResult]:
        """Run all loaded templates against the response context."""
        if not self._loaded:
            self.load_templates()

        ctx = ResponseContext(status_code=status_code, headers=headers, body=body)
        results: list[TemplateMatchResult] = []

        for tpl in self.templates:
            try:
                res = tpl.execute(ctx)
                if res:
                    results.append(res)
            except Exception:
                continue

        return results

    def scan_requests_response(self, resp: requests.Response) -> list[TemplateMatchResult]:
        """Convenience method to scan a requests.Response object directly."""
        return self.scan_response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text or "",
        )

    def to_tech_stack(self, results: list[TemplateMatchResult]) -> dict[str, list[str]]:
        """
        Convert matched template results into ThreatLens tech_stack format.
        Example output:
            {"jQuery": ["3.6.0"], "WordPress": ["detected"], "PHP": ["detected"]}
        """
        stack: dict[str, list[str]] = {}
        for r in results:
            tech_name = r.tech
            version = r.detected_version
            if tech_name not in stack:
                stack[tech_name] = [version]
            else:
                # If existing was 'detected' and new one has concrete version, upgrade it
                existing = stack[tech_name]
                if existing == ["detected"] and version != "detected":
                    stack[tech_name] = [version]
                elif version not in existing and version != "detected":
                    stack[tech_name].append(version)
        return stack

    def search_templates(
        self,
        query: str = "",
        tag: str | None = None,
        severity: str | None = None,
        category: str | None = None,
    ) -> list[Template]:
        """
        Search and filter templates by keyword, tag, severity, or category.
        """
        if not self._loaded:
            self.load_templates()

        query_lower = query.strip().lower()
        tag_lower = tag.strip().lower() if tag else None
        sev_upper = severity.strip().upper() if severity else None
        cat_lower = category.strip().lower() if category else None

        matched: list[Template] = []
        for tpl in self.templates:
            if query_lower:
                text_corpus = f"{tpl.id} {tpl.name} {tpl.description} {tpl.tech} {' '.join(tpl.tags)}".lower()
                if query_lower not in text_corpus:
                    continue

            if tag_lower and not any(tag_lower == t.lower() for t in tpl.tags):
                continue

            if sev_upper and tpl.severity != sev_upper:
                continue

            if cat_lower and tpl.category.lower() != cat_lower:
                continue

            matched.append(tpl)

        return matched

    def scan_target(
        self,
        base_url: str,
        request_fn,
        templates: list[Template] | None = None,
        max_paths: int = 15,
    ) -> list[TemplateMatchResult]:
        """
        Full Nuclei Multi-Path Scan:
        Resolves distinct paths across all templates, queries each path via request_fn
        with request pooling/deduplication, and evaluates matching templates.
        """
        if not self._loaded:
            self.load_templates()

        target_templates = templates if templates is not None else self.templates
        clean_base = base_url.rstrip("/")

        # Map each resolved URL to the templates that need it
        url_to_templates: dict[str, list[Template]] = {}
        for tpl in target_templates:
            for p in tpl.paths:
                resolved = p.replace("{{BaseURL}}", clean_base)
                if not resolved.startswith("http://") and not resolved.startswith("https://"):
                    resolved = f"{clean_base}/{resolved.lstrip('/')}"
                url_to_templates.setdefault(resolved, []).append(tpl)

        # Cap paths scanned to prevent runaway requests
        target_urls = list(url_to_templates.keys())[:max_paths]

        results: list[TemplateMatchResult] = []
        # Response cache for this scan
        response_cache: dict[str, ResponseContext] = {}

        for url in target_urls:
            tpl_list = url_to_templates[url]
            try:
                if url not in response_cache:
                    resp = request_fn(url)
                    ctx = ResponseContext(
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        body=resp.text or "",
                    )
                    response_cache[url] = ctx
                else:
                    ctx = response_cache[url]

                for tpl in tpl_list:
                    match_res = tpl.execute(ctx, matched_at=url)
                    if match_res:
                        results.append(match_res)
            except Exception:
                continue

        return results
