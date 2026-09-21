"""
JSON export — the machine-readable contract.

This is also the **only** interface between the Python analysis engine and the
Spring Boot backend.  The backend runs the engine as a subprocess and parses
exactly this document, so neither side can break the other by changing
internals.  Treat the shape here as an API.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Report, to_dict


def build(report: Report) -> dict[str, Any]:
    return to_dict(report)


def dumps(report: Report, indent: int | None = 2) -> str:
    return json.dumps(build(report), indent=indent, ensure_ascii=False)


def write(report: Report, path: str, indent: int | None = 2) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dumps(report, indent))
    return path
