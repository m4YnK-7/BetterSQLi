#!/usr/bin/env python3
"""
SQLi Orchestrator with persistent cookie/session support.

- Prompts user for DVWA cookies (PHPSESSID, security) if not found in config.
- Saves them to orchestrator/config.json.
- Includes cookies in all baseline requests and sqlmap runs automatically.
"""

import argparse
import os
import subprocess
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
import re
import requests

ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "runs"
CONFIG_PATH = Path(__file__).resolve().parent / "config.json"


def now_ts():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def load_or_create_config():
    """
    Loads orchestrator/config.json; prompts user for cookies if missing.
    """
    if CONFIG_PATH.exists():
        conf = json.loads(CONFIG_PATH.read_text())
    else:
        conf = {}

    # ensure cookies
    if "cookies" not in conf:
        print("\n🔐 Cookie setup (needed for DVWA authentication)")
        phpsessid = input("Enter your PHPSESSID (from DVWA browser): ").strip()
        sec_level = input("Enter DVWA security level (e.g., low/medium/high): ").strip()
        conf["cookies"] = {
            "PHPSESSID": phpsessid,
            "security": sec_level
        }
        CONFIG_PATH.write_text(json.dumps(conf, indent=2))
        print(f"✅ Saved cookies to {CONFIG_PATH}")
    return conf


def build_cookie_header(cookies_dict):
    return "; ".join([f"{k}={v}" for k, v in cookies_dict.items()])


def capture_baseline_request(url, cookies_dict, method="GET", headers=None, data=None):
    """
    Performs a baseline HTTP request to test access and response time.
    """
    headers = headers or {}
    session = requests.Session()
    session.cookies.update(cookies_dict)
    req = requests.Request(method.upper(), url, headers=headers, data=data)
    prepped = session.prepare_request(req)
    start = time.time()
    resp = session.send(prepped, verify=False, timeout=20)
    elapsed = (time.time() - start) * 1000.0

    req_text = f"{prepped.method} {prepped.path_url} HTTP/1.1\n"
    for k, v in prepped.headers.items():
        req_text += f"{k}: {v}\n"
    req_body = prepped.body or ""
    resp_text = f"HTTP/1.1 {resp.status_code}\n"
    for k, v in resp.headers.items():
        resp_text += f"{k}: {v}\n"
    return {
        "request": req_text + "\n" + (req_body if isinstance(req_body, str) else str(req_body)),
        "response": resp_text + "\n" + resp.text,
        "rt_ms": elapsed,
        "status": resp.status_code,
        "size": len(resp.content)
    }


def run_sqlmap(url, run_dir: Path, cookies_dict, extra_args=None, timeout=None):
    """
    Runs sqlmap with cookies included.
    """
    extra_args = extra_args or []
    cookie_header = build_cookie_header(cookies_dict)
    cmd = ["sqlmap", "-u", url, "--batch", "--cookie", cookie_header] + extra_args
    stdout_file = run_dir / "sqlmap.stdout.txt"
    stderr_file = run_dir / "sqlmap.stderr.txt"

    start = time.time()
    print(f"\n🚀 Running sqlmap:\n{' '.join(cmd)}\n")
    with stdout_file.open("wb") as out_f, stderr_file.open("wb") as err_f:
        proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    elapsed = time.time() - start
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_s": elapsed,
        "stdout": str(stdout_file),
        "stderr": str(stderr_file)
    }


def best_effort_extract(sqlmap_stdout_path: Path):
    """
    Extract databases/tables from sqlmap stdout for quick summary.
    """
    found = []
    if not sqlmap_stdout_path.exists():
        return found
    text = sqlmap_stdout_path.read_text(errors="ignore")
    db_pattern = re.compile(r"Database:\s*(\S+)", re.IGNORECASE)
    table_pattern = re.compile(r"Table:\s*(\S+)", re.IGNORECASE)
    for line in text.splitlines():
        if db_pattern.search(line):
            found.append({"type": "database", "value": db_pattern.search(line).group(1)})
        elif table_pattern.search(line):
            found.append({"type": "table", "value": table_pattern.search(line).group(1)})
    return found


def run(args):
    safe_mkdir(RUNS_DIR)
    conf = load_or_create_config()
    cookies_dict = conf["cookies"]
    cookie_str = build_cookie_header(cookies_dict)

    ts = now_ts()
    run_dir = RUNS_DIR / f"run_{ts}"
    safe_mkdir(run_dir)

    config_save = {
        "url": args.url,
        "method": args.method,
        "extra_args": args.extra_args or [],
        "cookies": cookies_dict,
        "timestamp": ts
    }
    (run_dir / "config.json").write_text(json.dumps(config_save, indent=2))

    print(f"\n📡 Capturing baseline request using cookies: {cookie_str}")
    try:
        baseline = capture_baseline_request(args.url, cookies_dict, method=args.method)
        (run_dir / "raw_http_0.txt").write_text(
            f"----- REQUEST -----\n{baseline['request']}\n\n"
            f"----- RESPONSE -----\n{baseline['response']}"
        )
    except Exception as e:
        baseline = {"error": str(e)}
        (run_dir / "raw_http_0.txt").write_text(f"ERROR: {e}")

    print("\n🧠 Starting SQLMap run ...")
    sqlmap_result = run_sqlmap(args.url, run_dir, cookies_dict, extra_args=args.extra_args, timeout=args.timeout)
    extracts = best_effort_extract(Path(sqlmap_result["stdout"]))

    summary = {
        "run_id": run_dir.name,
        "created_at": ts,
        "cookies_used": cookies_dict,
        "sqlmap_returncode": sqlmap_result["returncode"],
        "sqlmap_duration_s": sqlmap_result["duration_s"],
        "extract_count": len(extracts),
        "quick_summary": extracts[:10]
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    print("\n✅ Run complete.")
    print(f"Artifacts: {run_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLi Orchestrator with persistent cookie support.")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP method for baseline request")
    parser.add_argument("--extra-args", nargs="*", help="Extra sqlmap args (optional)")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout for sqlmap run")
    args = parser.parse_args()
    run(args)
