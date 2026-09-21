"""
Self-contained HTML forensic report.

One Jinja2 template produces the deliverable in two forms:
  * HTML  — this module, a single file with inlined CSS and no external assets
  * JSON  — ``json_report.py``, from the same objects

PDF is the same HTML printed by the browser; the ``@page`` rules are already in
the stylesheet and the template triggers printing when opened with ``?print=1``.
There is deliberately no server-side PDF renderer — see the note in the template
for what went wrong with the one there used to be.
"""

from __future__ import annotations

import os

from ..models import Report, to_dict

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
TEMPLATE_NAME = "report.html.j2"


def render_document(document: dict) -> str:
    """
    Render from the JSON document — the same dict ``json_report.build``
    produces.

    This is the entry point the API uses. A stored report has to be
    re-renderable long after the capture file itself is gone, and re-analysing
    the pcap to produce it would risk handing back a document that disagrees
    with the one on record: same evidence, different engine version, different
    findings. Rendering the persisted document instead means the HTML and the
    JSON are always two views of one artefact.
    """
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(TEMPLATE_NAME)
    return template.render(r=_Wrap(document))


def render(report: Report) -> str:
    return render_document(to_dict(report))


def write(report: Report, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report))
    return path


class _Wrap:
    """
    Attribute access over the plain dict produced by ``to_dict``.

    The template reads ``r.capture.filename`` rather than ``r['capture']['filename']``,
    which keeps it legible; this adapter provides that without dragging the
    dataclasses (and their enums and datetimes) into the template layer.
    """

    __slots__ = ("_d",)

    def __init__(self, d):
        object.__setattr__(self, "_d", d)

    def __getattr__(self, item):
        d = object.__getattribute__(self, "_d")
        if not isinstance(d, dict) or item not in d:
            return None
        return _wrap(d[item])

    def __getitem__(self, item):
        return self.__getattr__(item)

    def __bool__(self):
        return bool(object.__getattribute__(self, "_d"))

    def __iter__(self):
        return iter(object.__getattribute__(self, "_d"))

    def __str__(self):
        return str(object.__getattribute__(self, "_d"))


def _wrap(value):
    if isinstance(value, dict):
        return _Wrap(value)
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    return value
