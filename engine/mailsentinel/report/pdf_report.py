"""
PDF report generation using WeasyPrint.
"""

from __future__ import annotations

import io
from weasyprint import HTML

from ..models import Report
from .html_report import render_html


def generate_pdf(report: Report) -> bytes:
    """
    Render a Report into a PDF byte stream.
    """
    # 1. Render the HTML using the existing Jinja2 template
    html_content = render_html(report)
    
    # 2. Render that HTML to PDF
    # The html_content already has all the styles embedded
    pdf_bytes = HTML(string=html_content).write_pdf()
    
    return pdf_bytes
