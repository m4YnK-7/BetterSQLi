# /orchestrator/app.py
"""
Streamlit app: Control Panel (40%) + Live Console & Results (60%) + Toggleable Run History (right)

Features:
- All checkboxes / selectors requested (dbs, tables, columns, dump, dump-all, users, passwords, roles)
- Extra options: threads, level, risk, extra args
- Streams sqlmap output into UI
- After run, looks for dump/dvwa/users.csv and 'log' files under sqlmap output dir and offers preview + downloads
- Run History stored in /orchestrator/run_history.json
- Right-side toggleable Run History panel

Requirements:
- streamlit
- orchestrator.core (core.py in same folder)
- sqlmap binary accessible to the environment running Streamlit
"""

import streamlit as st
from pathlib import Path
import json
import time
import os
import sys
from datetime import datetime
from typing import Dict, Any

# Ensure orchestrator package is importable (if app.py runs from repository root)
ORCH_DIR = Path(__file__).resolve().parent
if str(ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(ORCH_DIR))

# Import core module (expects /orchestrator/core.py)
try:
    from orchestrator import core
except Exception as e:
    # attempt relative import fallback
    try:
        import core as core  # type: ignore
    except Exception:
        st.error(f"Could not import orchestrator.core: {e}")
        st.stop()

# Run history file
RUN_HISTORY_FILE = ORCH_DIR / "run_history.json"


def load_run_history():
    if RUN_HISTORY_FILE.exists():
        try:
            return json.loads(RUN_HISTORY_FILE.read_text())
        except Exception:
            return []
    return []


def save_run_history(history):
    try:
        RUN_HISTORY_FILE.write_text(json.dumps(history, indent=2))
    except Exception as e:
        st.error(f"Unable to save run history: {e}")


def add_run_history_entry(entry: Dict[str, Any]):
    history = load_run_history()
    history.insert(0, entry)  # newest first
    # cap history to 100 entries
    history = history[:100]
    save_run_history(history)


# Page config
st.set_page_config(page_title="Automated SQLi — Control Panel", layout="wide")

# Top header
st.markdown("<h1 style='margin-bottom:8px'>Automated SQLi — Control Panel</h1>", unsafe_allow_html=True)
st.markdown("Control Panel (left) — Live Console & Results (center) — Run History (right, toggleable)")

# Layout columns: left (40), center (60). We'll create a right column only when toggled.
left_col, center_col = st.columns([4,6])

# Right-side toggle (we'll render run history in a floating container on the right)
if "show_history" not in st.session_state:
    st.session_state.show_history = False

# Toggle button placed at top-right: simulate by a column of small width
right_toggle_col = st.columns([10,1])[1]
with right_toggle_col:
    if st.button("History ▶" if not st.session_state.show_history else "History ▼"):
        st.session_state.show_history = not st.session_state.show_history

# Left control panel
with left_col:
    st.subheader("Control Panel")
    target_url = st.text_input("Target URL (full)", value="http://192.168.56.10/vulnerabilities/sqli/?id=1")

    st.markdown("**Enumeration options**")
    dbs = st.checkbox("Enumerate databases (--dbs)", value=False)
    # DB selector (manual / will be filled if we implement auto-discovery)
    selected_db = st.text_input("Selected DB (for --tables/--columns/--dump) — type or leave blank", value="")
    tables = st.checkbox("Enumerate tables (--tables)", value=False)
    columns = st.checkbox("Enumerate columns (--columns)", value=False)

    st.markdown("**Quick enumerations**")
    users = st.checkbox("--users", value=False)
    passwords = st.checkbox("--passwords", value=False)
    roles = st.checkbox("--roles", value=False)

    st.markdown("**Dumping options (sensitive)**")
    dump = st.checkbox("Dump table (--dump) (select table below)", value=False)
    dump_all = st.checkbox("Dump ALL tables (--dump-all) — DANGEROUS", value=False)
    if dump_all:
        # explicit typed confirmation
        confirm = st.text_input("Type CONFIRM to enable --dump-all", value="")
        if confirm != "CONFIRM":
            st.warning("You must type CONFIRM to enable --dump-all.")
            dump_all = False

    selected_table = st.text_input("Selected Table (for --columns/--dump) — type or leave blank", value="")

    st.markdown("**Other options**")
    threads = st.number_input("Threads (--threads)", min_value=1, max_value=50, value=1)
    level = st.selectbox("Level (--level)", options=[None,1,2,3,4,5], index=0)
    risk = st.selectbox("Risk (--risk)", options=[None,1,2,3], index=0)
    extra_args = st.text_input("Extra raw sqlmap args (e.g. --random-agent)")

    st.markdown("---")
    run_btn = st.button("Run sqlmap", type="primary")
    st.caption("Note: Ensure sqlmap is installed and available to the process running this Streamlit app.")

# Center: live console + results
with center_col:
    st.subheader("Live Console & Results")
    console_area = st.empty()
    results_area = st.container()

# Right: Run History (toggleable)
if st.session_state.show_history:
    history_col = st.columns([1,3])[1]  # small spacer + column
    with history_col:
        st.subheader("Run History")
        history = load_run_history()
        if not history:
            st.info("No run history yet.")
        else:
            # show compact list
            for i, entry in enumerate(history):
                with st.expander(f"{entry.get('timestamp')} — {entry.get('target')} — {entry.get('summary', '')}", expanded=(i==0)):
                    st.write("Started:", entry.get("timestamp"))
                    st.write("Target:", entry.get("target"))
                    st.write("Options:", entry.get("options", {}))
                    st.write("Return code:", entry.get("returncode"))
                    st.write("Output dir:", entry.get("output_dir"))
                    if entry.get("dump_path"):
                        if Path(entry["dump_path"]).exists():
                            st.download_button(f"Download dump ({i+1})", data=Path(entry["dump_path"]).read_bytes(), file_name=Path(entry["dump_path"]).name)
                        st.code(entry.get("dump_preview","(no preview)"), language="text")
                    if entry.get("log_path"):
                        if Path(entry["log_path"]).exists():
                            st.download_button(f"Download log ({i+1})", data=Path(entry["log_path"]).read_bytes(), file_name=Path(entry["log_path"]).name)
                        st.code(entry.get("log_preview","(no preview)"), language="text")
                    # small action buttons
                    if entry.get("output_dir") and Path(entry["output_dir"]).exists():
                        st.write(f"Files in output dir: {len(list(Path(entry['output_dir']).glob('**/*')))}")
                    st.markdown("---")

# Run logic
if run_btn:
    if not target_url:
        st.error("Please provide a target URL.")
    else:
        options = {
            "dbs": dbs,
            "tables": tables,
            "columns": columns,
            "dump": dump,
            "dump_all": dump_all,
            "users": users,
            "passwords": passwords,
            "roles": roles,
            "selected_db": selected_db.strip() or None,
            "selected_table": selected_table.strip() or None,
            "threads": int(threads),
            "level": int(level) if level else None,
            "risk": int(risk) if risk else None,
            "extra_args": extra_args.strip() or None,
        }

        # Run sqlmap and stream output
        console_lines = []
        output_preview = ""
        console_area.code("Starting sqlmap...\n", language="bash")
        start_ts = datetime.utcnow().isoformat() + "Z"
        start_time = time.time()
        returncode = None
        output_dir = None
        try:
            for chunk in core.run_sqlmap_stream(target_url, options):
                # append to console text and show (stream)
                console_lines.append(chunk)
                console_text = "".join(console_lines)
                console_area.code(console_text, language="bash")
                # small throttle to keep UI responsive
                time.sleep(0.01)
            # If run_sqlmap_stream returned a tuple, capture it (our core yields then returns)
            # Note: our generator yields strings and then returns a tuple (returncode, output_dir).
            # But Python generator return value isn't directly accessible here — core.run_sqlmap_stream was implemented as a generator that yields lines and then uses `return (returncode, output_dir)`.
            # To be safe, after the loop attempt to determine output dir using core.get_sqlmap_output_dir heuristic:
            host = target_url
            if "://" in host:
                host = host.split("://",1)[1]
            host = host.split("/",1)[0]
            output_dir = core.get_sqlmap_output_dir(host)
            # attempt to determine return code by looking into console or core functions (best-effort)
            # We'll set returncode to 0 if no "ERROR" found, else -1 (best-effort heuristic)
            console_join = "".join(console_lines).lower()
            if "error" in console_join or "exception" in console_join:
                returncode = -1
            else:
                returncode = 0
        except Exception as e:
            console_area.code(f"Exception running sqlmap: {e}", language="bash")
            returncode = -2

        # Attempt to extract dump & log
        res = {}
        if output_dir and Path(output_dir).exists():
            res = core.extract_dump_and_log(Path(output_dir), dump_rel="dump/dvwa/users.csv")
        else:
            # still try with heuristics (in case core.get_sqlmap_output_dir returned non-existent path)
            res = {"output_dir": str(output_dir) if output_dir else "(not detected)"}

        # Show summary & results
        with results_area:
            st.markdown("### Run Summary")
            st.write("Target:", target_url)
            st.write("Started (UTC):", start_ts)
            st.write("Elapsed (s):", round(time.time() - start_time, 2))
            st.write("Return code (heuristic):", returncode)
            st.write("Detected sqlmap output dir:", res.get("output_dir"))

            if res.get("dump_path"):
                st.markdown("#### Found dump file (users.csv)")
                dump_path = Path(res["dump_path"])
                st.write(str(dump_path))
                try:
                    st.download_button("Download users.csv", data=dump_path.read_bytes(), file_name=dump_path.name)
                except Exception:
                    st.warning("Unable to load dump file into memory for download (file may be large).")
                st.text_area("users.csv (preview)", value=res.get("dump_preview", ""), height=200)
            else:
                st.info("No dump/dvwa/users.csv found in the output directory.")

            if res.get("log_path"):
                st.markdown("#### Log file")
                log_path = Path(res["log_path"])
                st.write(str(log_path))
                try:
                    st.download_button("Download log", data=log_path.read_bytes(), file_name=log_path.name)
                except Exception:
                    st.warning("Unable to load log file into memory for download (file may be large).")
                st.text_area("log (preview)", value=res.get("log_preview", ""), height=200)
            else:
                st.info("No log found in the output directory.")

        # Save run history entry
        summary = ", ".join([k for k,v in options.items() if v and k in ("dbs","tables","columns","dump","dump_all","users","passwords","roles")])
        entry = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
            "target": target_url,
            "options": options,
            "summary": summary,
            "returncode": returncode,
            "output_dir": res.get("output_dir"),
            "dump_path": res.get("dump_path"),
            "dump_preview": (res.get("dump_preview")[:2000] if res.get("dump_preview") else None),
            "log_path": res.get("log_path"),
            "log_preview": (res.get("log_preview")[:2000] if res.get("log_preview") else None),
        }
        add_run_history_entry(entry)
        st.success("Run finished and recorded to history.")

# Footer / quick tips
st.markdown("---")
st.markdown("**Tips:** If sqlmap isn't found, ensure the binary is on PATH for the user running Streamlit, or edit `core.py` to point to the full `sqlmap` path. For DB/table auto-discovery and dropdowns, we can add parsing of sqlmap output to populate selectors automatically — tell me and I'll add it.")
