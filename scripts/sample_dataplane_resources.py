#!/usr/bin/env python3
"""Read-only RSS/FD sampling for a known soak PID; never collect argv or paths."""
import argparse
import datetime
import json
import pathlib
import shutil
import subprocess
import time


def sample_process(pid):
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart=", "-o", "rss=", "-o", "time=", "-o", "etime="],
        capture_output=True, text=True, timeout=5, check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    fields = result.stdout.split()
    if len(fields) != 8 or not fields[5].isdigit():
        raise RuntimeError("unexpected ps output format; no raw process data logged")
    record = {"pid": pid, "process_started": " ".join(fields[:5]), "rss_kib": int(fields[5]), "cpu_time": fields[6], "process_elapsed": fields[7]}
    executable = shutil.which("lsof")
    record["fd_count"] = None
    if executable:
        result = subprocess.run([executable, "-a", "-p", str(pid), "-F", "f"], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0:
            # Only numeric descriptors; exclude cwd/root/executable mappings.
            descriptors = {line[1:] for line in result.stdout.splitlines() if line.startswith("f") and line[1:].isdigit()}
            record["fd_count"] = len(descriptors)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--interval", type=float, default=60)
    parser.add_argument("--seconds", type=float, default=1860)
    args = parser.parse_args()
    if args.pid <= 1 or not 1 <= args.interval <= 3600 or not 1 <= args.seconds <= 90000:
        parser.error("invalid PID, interval or observation duration")
    started = time.monotonic()
    identity = None
    with args.output.open("a", buffering=1) as output:
        while time.monotonic() - started <= args.seconds:
            try:
                record = sample_process(args.pid)
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                output.write(json.dumps({"event": "sampling_failed", "pid": args.pid, "error_type": type(error).__name__}) + "\n")
                return 1
            if record is None:
                output.write(json.dumps({"event": "process_unavailable", "pid": args.pid, "elapsed_seconds": time.monotonic() - started}) + "\n")
                return
            if identity is not None and record["process_started"] != identity:
                output.write(json.dumps({"event": "pid_reused", "pid": args.pid}) + "\n")
                return
            identity = record["process_started"]
            record.update({"event": "resource_sample", "sampled_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "elapsed_seconds": time.monotonic() - started})
            output.write(json.dumps(record) + "\n")
            time.sleep(min(args.interval, max(0, args.seconds - (time.monotonic() - started))))


if __name__ == "__main__":
    raise SystemExit(main())
