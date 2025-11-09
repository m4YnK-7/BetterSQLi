# /orchestrator/core.py
import subprocess
import shlex
import os
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            return {}
    return {}

CONFIG = load_config()

# Default sqlmap output base dir (can be overridden in config.json)
DEFAULT_SQLMAP_OUTPUT_BASE = CONFIG.get(
    "sqlmap_output_base", "/home/kali/.local/share/sqlmap/output"
)


def get_sqlmap_output_dir(target: str) -> Path:
    """
    Compute the sqlmap output dir for the given target (IP or host).
    Default: /home/kali/.local/share/sqlmap/output/<target>
    You may override 'sqlmap_output_base' in config.json.
    """
    base = Path(CONFIG.get("sqlmap_output_base", DEFAULT_SQLMAP_OUTPUT_BASE))
    # sqlmap often replaces : with _ or uses IP directly; we'll keep the raw target string.
    # Allow both: exact target dir or sanitized:
    candidate1 = base / target
    if candidate1.exists():
        return candidate1
    # fallback: try to sanitize common characters
    sanitized = target.replace("://", "_").replace("/", "_").replace(":", "_")
    candidate2 = base / sanitized
    return candidate2 if candidate2.exists() else candidate1


def find_dump_csv(output_dir: Path, relative_path: str = "dump/dvwa/users.csv") -> Optional[Path]:
    """
    Return path to dump file if it exists.
    """
    p = output_dir / relative_path
    if p.exists():
        return p
    return None


def find_log_file(output_dir: Path, logname: str = "log") -> Optional[Path]:
    """
    Many sqlmap runs produce files named 'log' or distinct .log files under the output dir.
    We'll check for a file named 'log' and for any '*.log' top-level files.
    """
    p = output_dir / logname
    if p.exists():
        return p
    # find any .log files
    log_files = list(output_dir.glob("*.log"))
    if log_files:
        # return the newest
        return max(log_files, key=lambda f: f.stat().st_mtime)
    return None


def read_file_preview(path: Path, max_lines: int = 200) -> str:
    """
    Return first `max_lines` lines of the file (safe preview).
    """
    try:
        with path.open("r", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                lines.append(line.rstrip("\n"))
                if i + 1 >= max_lines:
                    lines.append("... (truncated preview)")
                    break
            return "\n".join(lines)
    except Exception as e:
        return f"Unable to read file {str(path)}: {e}"


def build_sqlmap_args(target_url: str, options: Dict[str, Any]) -> List[str]:
    """
    Build the sqlmap command line argument list from the selected options.
    options keys expected (booleans & strings):
      - dbs, tables, columns, dump, dump_all, users, passwords, roles
      - selected_db (str) required when tables True
      - selected_table (str) required when columns/dump True
      - threads, risk, level, extra_args (str)
    """
    args = ["sqlmap", "-u", target_url, "--batch", "--answers=follow=Y"]
    # Risk/level/thread options if passed
    if options.get("risk"):
        args += ["--risk", str(options["risk"])]
    if options.get("level"):
        args += ["--level", str(options["level"])]
    if options.get("threads"):
        args += ["--threads", str(options["threads"])]

    # Enumeration options
    if options.get("dbs"):
        args.append("--dbs")

    if options.get("tables"):
        # requires db selection
        sel_db = options.get("selected_db")
        if sel_db:
            args += ["--tables", "-D", sel_db]
        else:
            # If no DB provided, we still request tables (sqlmap may ask or error)
            args.append("--tables")

    if options.get("columns"):
        sel_table = options.get("selected_table")
        sel_db = options.get("selected_db")
        if sel_db:
            args += ["-D", sel_db]
        if sel_table:
            args += ["--columns", "-T", sel_table]
        else:
            args.append("--columns")

    # Quick enumerations
    if options.get("users"):
        args.append("--users")
    if options.get("passwords"):
        args.append("--passwords")
    if options.get("roles"):
        args.append("--roles")

    # Dump options
    if options.get("dump_all"):
        args.append("--dump-all")
    elif options.get("dump"):
        sel_db = options.get("selected_db")
        sel_table = options.get("selected_table")
        if sel_db:
            args += ["-D", sel_db]
        if sel_table:
            args += ["--dump", "-T", sel_table]
        else:
            args.append("--dump")

    # Add any extra raw sqlmap args
    extra = options.get("extra_args")
    if extra:
        # split safely
        args += shlex.split(extra)

    return args


def run_sqlmap_stream(target_url: str, options: Dict[str, Any], cwd: Optional[str] = None, timeout: Optional[int] = None):
    """
    Run sqlmap with the constructed args, stream output (generator style).
    Returns a tuple (returncode, output_dir_path) when finished.
    This function yields stdout/stderr lines as they arrive (useful for UI streaming).
    """
    args = build_sqlmap_args(target_url, options)
    # ensure we run with full path resolution
    cmd_display = " ".join(shlex.quote(a) for a in args)
    yield f"> {cmd_display}\n"
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd or None,
            text=True,
            bufsize=1,
            universal_newlines=True,
            errors="replace",
        )
    except FileNotFoundError as e:
        yield f"ERROR: sqlmap executable not found: {e}\n"
        returncode = -1
        # attempt to guess output dir
        output_dir = None
        return (returncode, output_dir)

    # stream stdout line by line
    try:
        start = time.time()
        for line in proc.stdout:
            yield line
            # optional timeout hook
            if timeout and (time.time() - start) > timeout:
                proc.kill()
                yield "\nProcess killed due to timeout.\n"
                break
        proc.wait()
        returncode = proc.returncode
    except Exception as e:
        yield f"\nException while running sqlmap: {e}\n"
        proc.kill()
        returncode = -2

    # Attempt to determine output dir based on target_url
    # Prefer using host/IP only portion for a path (simple heuristic)
    # strip scheme
    host = target_url
    if "://" in host:
        host = host.split("://", 1)[1]
    # remove path part
    host = host.split("/", 1)[0]
    output_dir = get_sqlmap_output_dir(host)
    yield f"\nProcess finished with return code {returncode}. sqlmap output dir: {str(output_dir)}\n"
    return (returncode, output_dir)


def extract_dump_and_log(output_dir: Path, dump_rel: str = "dump/dvwa/users.csv") -> Dict[str, Any]:
    """
    Inspect the computed output_dir and return found files and previews.
    Returns dict with keys:
      - output_dir (str)
      - dump_path (str|None)
      - dump_preview (str|None)
      - log_path (str|None)
      - log_preview (str|None)
    """
    res = {
        "output_dir": str(output_dir),
        "dump_path": None,
        "dump_preview": None,
        "log_path": None,
        "log_preview": None,
    }
    try:
        if not output_dir.exists():
            return res

        dump_file = find_dump_csv(output_dir, dump_rel)
        if dump_file:
            res["dump_path"] = str(dump_file)
            res["dump_preview"] = read_file_preview(dump_file, max_lines=400)

        log_file = find_log_file(output_dir, logname="log")
        if log_file:
            res["log_path"] = str(log_file)
            res["log_preview"] = read_file_preview(log_file, max_lines=400)

    except Exception as e:
        res["error"] = f"Error extracting files: {e}"
    return res
