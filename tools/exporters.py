"""
Export helpers for raw HTTP files.

Currently supports converting the saved `raw_http_<n>.txt` into a single HTTP request
file suitable to paste into Burp Repeater or save for manual use.
"""
from pathlib import Path

def export_to_burp(raw_http_path: Path, out_path: Path):
    """
    Read a raw_http file (written by the orchestrator) and write a Burp-friendly file.
    The simple format is just the request section (headers + body).
    """
    txt = raw_http_path.read_text(errors="ignore")
    # Attempts to split into REQUEST / RESPONSE sections
    if "----- REQUEST -----" in txt:
        parts = txt.split("----- REQUEST -----", 1)[1]
        # If response part exists, remove it
        if "----- RESPONSE -----" in parts:
            parts = parts.split("----- RESPONSE -----", 1)[0]
        content = parts.strip()
    else:
        # fallback: write whole file
        content = txt
    out_path.write_text(content)
    return out_path
