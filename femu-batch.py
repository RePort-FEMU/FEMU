#!/usr/bin/env python3
"""
Run FEMU in parallel Docker containers, one per firmware file.

Usage:
    python femu-batch.py -i ./firmwares -o ./output -j 4 -m check
"""

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path


_STAGE_ABBREV: dict[str, str] = {
    "success":           "s",
    "partial_success":   "ps",
    "extraction_failed": "ef",
    "probe_failed":      "pf",
    "timeout":           "to",
    "unknown":           "u",
}

def _abbrev(stage: str) -> str:
    if stage in _STAGE_ABBREV:
        return _STAGE_ABBREV[stage]
    if stage.startswith("error:") or stage.startswith("exception:"):
        return "err"
    return stage[:4]


def run_single(firmware: Path, output_dir: Path, subdir: Path, image: str, mode: str, extra: list[str]) -> dict:
    fw_output = output_dir / subdir / firmware.stem
    fw_output.mkdir(parents=True, exist_ok=True)

    container_name = f"femu-{firmware.stem}-{uuid.uuid4().hex[:8]}"
    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--privileged",
        "--device", "/dev/net/tun",
        "-e", f"PUID={os.getuid()}",
        "-e", f"PGID={os.getgid()}",
        "-v", f"{firmware.resolve()}:/input/{firmware.name}:ro",
        "-v", f"{fw_output.resolve()}:/output",
        image,
        "-i", f"/input/{firmware.name}",
        "-m", mode,
        *extra,
    ]

    result: dict = {"firmware": str(subdir / firmware.name), "output_dir": str(fw_output), "stage": "unknown"}

    log_path = fw_output / "container.log"
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
            try:
                stdout, stderr = proc.communicate(timeout=3600)
            except subprocess.TimeoutExpired:
                subprocess.run(["docker", "stop", container_name], capture_output=True)
                proc.wait()
                stdout, stderr = proc.communicate()
                result["stage"] = "timeout"
            else:
                result["returncode"] = proc.returncode
            result["log_path"] = str(log_path)
            log_path.write_text(stdout + stderr, errors="replace")
    except Exception as e:
        result["stage"] = f"error: {e}"
        return result

    for findings_path in fw_output.glob("workDir/*/findings.json"):
        try:
            with open(findings_path) as f:
                findings = json.load(f)
            result["stage"] = findings.get("stage", "unknown")
            result["findings"] = findings
        except Exception:
            pass
        break

    return result


def main():
    parser = argparse.ArgumentParser(description="Batch-run FEMU across a firmware directory.")
    parser.add_argument("-i", "--input",  required=True,      help="Directory of firmware files")
    parser.add_argument("-o", "--output", default="./output", help="Root output directory")
    parser.add_argument("-j", "--jobs",   type=int, default=4, help="Max parallel containers")
    parser.add_argument("-m", "--mode",   default="check",    help="FEMU mode (default: check)")
    parser.add_argument("--image",        default="femu",     help="Docker image (default: femu)")
    parser.add_argument("extra", nargs=argparse.REMAINDER,    help="Extra args forwarded to femu")
    args = parser.parse_args()

    extra = [a for a in args.extra if a != "--"]

    input_dir  = Path(args.input)
    output_dir = Path(args.output)

    if not input_dir.is_dir():
        print(f"error: {input_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    # Collect (firmware_path, subdir) pairs — supports flat or one-level brand/firmware layout
    firmware_files: list[tuple[Path, Path]] = []
    for item in sorted(input_dir.iterdir()):
        if item.is_file():
            firmware_files.append((item, Path(".")))
        elif item.is_dir():
            for fw in sorted(item.iterdir()):
                if fw.is_file():
                    firmware_files.append((fw, Path(item.name)))

    if not firmware_files:
        print(f"error: no files found in {input_dir}", file=sys.stderr)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Running {len(firmware_files)} firmware(s) with {args.jobs} parallel containers...\n")

    results = []
    stage_counts: dict[str, int] = {}
    total_fw = len(firmware_files)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(run_single, fw, output_dir, subdir, args.image, args.mode, extra): (fw, subdir)
            for fw, subdir in firmware_files
        }
        for future in concurrent.futures.as_completed(futures):
            fw, subdir = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"firmware": str(subdir / fw.name), "stage": f"exception: {e}"}
            results.append(result)
            rc = result.get("returncode", "?")
            stage = result.get("stage", "unknown")
            log = result.get("log_path", "")
            ab = _abbrev(stage)
            stage_counts[ab] = stage_counts.get(ab, 0) + 1
            counters = "  ".join(f"{s}:{n}" for s, n in sorted(stage_counts.items()))
            print(f"  [{ab:4s}]  {result['firmware']:60s}  (rc={rc})  [{len(results)}/{total_fw} | {counters}]  → {log}")

    total   = len(results)
    success = sum(1 for r in results if r.get("stage") == "success")

    print(f"\n{'='*60}")
    print(f"Done:  {total} firmware(s)  |  success: {success}  |  failed: {total - success}")

    summary_path = output_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump([{k: v for k, v in r.items() if k != "output"} for r in results],
                  f, indent=2, default=str)
    print(f"Summary → {summary_path}")


if __name__ == "__main__":
    main()
