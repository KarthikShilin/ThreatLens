# engine/__init__.py
"""
Nuclei-inspired declarative template and matching engine for ThreatLens.
"""

from .matcher import Matcher
from .extractor import Extractor
from .template import Template, TemplateMatchResult
from .runner import NucleiEngine

__all__ = ["Matcher", "Extractor", "Template", "TemplateMatchResult", "NucleiEngine"]
