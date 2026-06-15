#!/usr/bin/env python3
"""
Run FEMU in parallel Docker containers, one per firmware file.

Usage:
    python femu-batch.py -i ./firmwares -o ./output -j 4 -m check

Resume a previous run, skipping firmwares that already fully succeeded and
re-running the failed / partially-successful ones:
    python femu-batch.py -i ./firmwares -o ./output -j 4 -m check --resume

Resume only the firmwares that stopped at a specific stage (e.g. re-run just the
ones whose previous run ended at 'preparation_failed'), skipping everything else:
    python femu-batch.py -i ./firmwares -o ./output --resume-stage preparation_failed
"""

import argparse
import concurrent.futures
import json
import os
import shutil
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


def _read_findings(fw_output: Path) -> dict | None:
    """Return the parsed findings.json for a firmware output dir, or None if absent/unreadable."""
    for findings_path in fw_output.glob("workDir/*/findings.json"):
        try:
            with open(findings_path) as f:
                return json.load(f)
        except Exception:
            return None
    return None


def existing_result(firmware: Path, output_dir: Path, subdir: Path) -> dict | None:
    """Build a result dict from a previous run's findings, or None if there is no prior run."""
    fw_output = output_dir / subdir / firmware.stem
    findings = _read_findings(fw_output)
    if findings is None:
        return None
    return {
        "firmware": str(subdir / firmware.name),
        "output_dir": str(fw_output),
        "stage": findings.get("stage", "unknown"),
        "findings": findings,
        "skipped": True,
    }


def run_single(firmware: Path, output_dir: Path, subdir: Path, image: str, mode: str, extra: list[str]) -> dict:
    fw_output = output_dir / subdir / firmware.stem
    # Start each (re-)run from a clean slate so stale artifacts from a previous
    # failed/partial attempt can't be mistaken for this run's results.
    if fw_output.exists():
        shutil.rmtree(fw_output, ignore_errors=True)
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

    findings = _read_findings(fw_output)
    if findings is not None:
        result["stage"] = findings.get("stage", "unknown")
        result["findings"] = findings

    return result


def main():
    parser = argparse.ArgumentParser(description="Batch-run FEMU across a firmware directory.")
    parser.add_argument("-i", "--input",  required=True,      help="Directory of firmware files")
    parser.add_argument("-o", "--output", default="./output", help="Root output directory")
    parser.add_argument("-j", "--jobs",   type=int, default=4, help="Max parallel containers")
    parser.add_argument("-m", "--mode",   default="check",    help="FEMU mode (default: check)")
    parser.add_argument("--image",        default="femu",     help="Docker image (default: femu)")
    parser.add_argument("--resume", action="store_true",
                        help="Reuse an existing output directory: skip firmwares that already "
                             "reached stage 'success' and re-run the failed/partial ones.")
    parser.add_argument("--resume-stage", metavar="STAGE", action="append",
                        help="Like --resume, but only (re-)run firmwares whose previous run ended "
                             "at one of the given stages (e.g. 'preparation_failed'); every other "
                             "firmware is skipped. Repeat the flag or pass a comma-separated list "
                             "to target multiple stages. Implies --resume.")
    parser.add_argument("extra", nargs=argparse.REMAINDER,    help="Extra args forwarded to femu")
    args = parser.parse_args()

    extra = [a for a in args.extra if a != "--"]

    # --resume-stage implies --resume and narrows the re-run set to the given stages.
    target_stages: set[str] | None = None
    if args.resume_stage:
        target_stages = {
            stage.strip()
            for entry in args.resume_stage
            for stage in entry.split(",")
            if stage.strip()
        }
        args.resume = True

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

    # In --resume mode, partition firmwares into skipped (kept from the prior run)
    # and to-be-(re)run. Without --resume-stage, anything that didn't reach
    # 'success' is re-run; with --resume-stage, only firmwares whose prior run
    # ended at one of the target stages is re-run and everything else is skipped.
    skipped_results: list[dict] = []
    to_run: list[tuple[Path, Path]] = []
    for fw, subdir in firmware_files:
        if args.resume:
            prev = existing_result(fw, output_dir, subdir)
            if target_stages is not None:
                if prev is not None and prev["stage"] in target_stages:
                    to_run.append((fw, subdir))
                elif prev is not None:
                    skipped_results.append(prev)
                # No prior run and a stage filter is set → nothing to target; skip it.
                continue
            if prev is not None and prev["stage"] == "success":
                skipped_results.append(prev)
                continue
        to_run.append((fw, subdir))

    total_fw = len(firmware_files)
    if target_stages is not None:
        print(f"Resume (stages: {', '.join(sorted(target_stages))}): {total_fw} firmware(s) — "
              f"skipping {len(skipped_results)}, (re-)running {len(to_run)} matching firmware(s) "
              f"with {args.jobs} parallel containers...\n")
    elif args.resume:
        print(f"Resume: {total_fw} firmware(s) — skipping {len(skipped_results)} already-successful, "
              f"(re-)running {len(to_run)} with {args.jobs} parallel containers...\n")
    else:
        print(f"Running {total_fw} firmware(s) with {args.jobs} parallel containers...\n")

    # Seed results and the live stage counters with the skipped successes.
    results: list[dict] = list(skipped_results)
    stage_counts: dict[str, int] = {}
    for r in skipped_results:
        ab = _abbrev(r["stage"])
        stage_counts[ab] = stage_counts.get(ab, 0) + 1
    for r in skipped_results:
        print(f"  [{'skip:'+r['stage']:20s}]  {r['firmware']:70s}  (cached)  [{len(results)}/{total_fw}]")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(run_single, fw, output_dir, subdir, args.image, args.mode, extra): (fw, subdir)
            for fw, subdir in to_run
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
            print(f"  [{stage:20s}]  {result['firmware']:70s}  (rc={rc})  [{len(results)}/{total_fw} | {counters}]  → {log}")

    total   = len(results)
    success = sum(1 for r in results if r.get("stage") == "success")

    print(f"\n{'='*60}")
    print(f"Done:  {total} firmware(s)  |  success: {success}  |  failed: {total - success}")
    if target_stages is not None:
        print(f"       ({len(skipped_results)} skipped, {len(to_run)} (re-)run "
              f"matching stages: {', '.join(sorted(target_stages))})")
    elif args.resume:
        print(f"       ({len(skipped_results)} skipped as already-successful, {len(to_run)} (re-)run)")

    summary_path = output_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump([{k: v for k, v in r.items() if k != "output"} for r in results],
                  f, indent=2, default=str)
    print(f"Summary → {summary_path}")


if __name__ == "__main__":
    main()
