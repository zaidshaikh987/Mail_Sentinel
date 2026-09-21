from __future__ import annotations

import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEMO_DIR = os.path.join(REPO_ROOT, "demo-pcaps")

DEMO_FILES = {
    "imap_cleartext": "imap.cap",
    "pop3_starttls": "pop-ssl.pcapng",
    "smtp_submission_cleartext": "sample-imf.pcap.gz",
    "smtp_starttls": "smtp-ssl.pcapng",
    "smtp_relay_cleartext": "smtp.pcap",
    # Synthetic, and the only capture that exercises the good end of the
    # scale. See scripts/make_demo_capture.py for how it is built and why.
    "imaps_tls13": "synthetic-imaps-tls13.pcap",
}


def demo_path(key: str) -> str:
    return os.path.join(DEMO_DIR, DEMO_FILES[key])


@pytest.fixture(scope="session")
def demo_dir() -> str:
    if not os.path.isdir(DEMO_DIR):
        pytest.skip(f"demo captures not found at {DEMO_DIR}")
    return DEMO_DIR


@pytest.fixture(scope="session")
def captures(demo_dir):
    """All demo captures that are actually present, keyed by role."""
    out = {}
    for key, name in DEMO_FILES.items():
        p = os.path.join(demo_dir, name)
        if os.path.exists(p):
            out[key] = p
    if not out:
        pytest.skip("no demo captures present")
    return out


@pytest.fixture(scope="session")
def analysed(captures):
    """Every demo capture run through the full pipeline once, cached."""
    from mailsentinel.pipeline import analyse_capture

    return {k: analyse_capture(p, run_ml=False) for k, p in captures.items()}
