#!/usr/bin/env python
"""Export reproducible read-only IDA evidence without manually opening a GUI.

The input binary/database is always copied to a temporary working directory.
Analysis never opens the original database for writing. No shell or arbitrary
model-generated Python is executed. The output can be replayed offline.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
READ_COMMANDS = {"get_status", "decompile", "get_callees", "get_xrefs", "get_basic_blocks",
                 "build_dominator_tree", "get_dominator_context", "calculate_tis",
                 "find_blocking_checks", "scan_auth_patterns", "analyze_guard_coverage",
                 "scan_args", "get_imports", "get_functions", "get_segments", "search_strings",
                 "scan_global_blocking_usage", "get_storage_accesses"}


def export_snapshot(ida_path, target, output, functions=("main",), queries=(), timeout=300):
    ida_path, target, output = Path(ida_path).resolve(), Path(target).resolve(), Path(output).resolve()
    if not ida_path.is_file() or not target.is_file():
        raise ValueError("IDA executable and input must be existing files")
    if output == target or timeout <= 0:
        raise ValueError("Use a separate output file and a positive timeout")
    requests = [{"command": "get_status", "params": {}}]
    for function in functions:
        for command in ("decompile", "get_callees", "get_basic_blocks", "build_dominator_tree",
                        "calculate_tis", "scan_auth_patterns"):
            requests.append({"command": command, "params": {"address": function}})
        requests.append({"command": "get_xrefs", "params": {"address": function, "direction": "to"}})
    requests.extend(queries)
    if len(requests) > 512 or any(not isinstance(q, dict) or q.get("command") not in READ_COMMANDS
                                  or not isinstance(q.get("params", {}), dict) for q in requests):
        raise ValueError("Snapshot accepts at most 512 read-only queries")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pangu_ida_") as directory:
        scratch = Path(directory)
        copy = scratch / target.name
        shutil.copy2(target, copy)
        script, log = scratch / "export.py", output.with_suffix(".ida.log")
        snapshot = scratch / "snapshot.json"
        script.write_text(
            "import sys, os, json, runpy, traceback\n"
            f"sys.path[:0] = {[str(ROOT), str(ROOT / 'core' / 'bridge')]!r}\n"
            "import ida_auto, ida_pro\n"
            "os.environ['PANGU_NO_AUTOSTART'] = '1'\n"
            "code = 1\n"
            "try:\n"
            "    ida_auto.auto_wait()\n"
            f"    namespace = runpy.run_path({str(ROOT / 'core' / 'bridge' / 'ida_server.py')!r})\n"
            "    agent = namespace['IDAServerAgent']()\n"
            f"    requests = {requests!r}\n"
            "    records = [dict(q, result=agent._dispatch_logic(q)) for q in requests]\n"
            "    data = {'schema_version': 1, 'queries': records}\n"
            f"    with open({str(snapshot)!r}, 'w', encoding='utf-8') as stream:\n"
            "        json.dump(data, stream, indent=2, ensure_ascii=False)\n"
            "    code = 0 if all(r['result'].get('status') == 'ok' for r in records) else 2\n"
            "except Exception:\n"
            "    traceback.print_exc()\n"
            "finally:\n"
            "    ida_pro.qexit(code)\n", encoding="utf-8")
        command = [str(ida_path), "-A", f"-L{log}", f"-S{script}", str(copy)]
        result = subprocess.run(command, timeout=timeout, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        if not snapshot.is_file() or result.returncode not in {0, 2}:
            raise RuntimeError(f"IDA failed (exit {result.returncode}); inspect {log}")
        data = json.loads(snapshot.read_text(encoding="utf-8"))
        if data.get("schema_version") != 1 or len(data.get("queries", [])) != len(requests):
            raise RuntimeError("IDA produced an incomplete snapshot")
        # Preserve previous results when a launch fails and publish complete JSON
        # atomically within the destination filesystem.
        with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".json", delete=False) as staged:
            staged.write(snapshot.read_bytes())
            staged_path = Path(staged.name)
        try:
            staged_path.replace(output)
        finally:
            staged_path.unlink(missing_ok=True)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="Binary, .i64 or .idb database")
    parser.add_argument("--ida-path", default=os.environ.get("IDA_PATH"), required=not bool(os.environ.get("IDA_PATH")))
    parser.add_argument("--output", required=True)
    parser.add_argument("--functions", nargs="*", default=["main"])
    parser.add_argument("--queries", help="JSON file containing extra bounded read requests")
    parser.add_argument("--storage", action="store_true", help="Extract constant NVRAM read/write keys")
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    queries = json.loads(Path(args.queries).read_text(encoding="utf-8")) if args.queries else []
    if args.storage:
        queries.append({"command": "get_storage_accesses", "params": {}})
    return export_snapshot(args.ida_path, args.target, args.output, args.functions, queries, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
