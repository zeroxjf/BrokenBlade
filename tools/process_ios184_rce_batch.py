#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import re
import subprocess
import sys
from pathlib import Path

import build_ios18_rce_offset_candidates as rce_build
import derive_ios18_manual_offsets as manual_build
import extract_ios18_symbol_offsets as symbol_build


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "firmware"
WORK = FIRMWARE / "work"
MANIFEST = WORK / "ios184_rce_target_manifest.json"

REPORTS = {
    "symbol": WORK / "ios184_rce_symbol_offsets_report.json",
    "manual": WORK / "ios184_rce_manual_offsets_report.json",
    "rce": WORK / "ios184_rce_offset_candidates.json",
}


def run(args, stdout=None):
    return subprocess.run(args, cwd=ROOT, text=True, stdout=stdout, stderr=subprocess.STDOUT, check=True)


def load_json(path, default):
    if path.exists():
        return json.loads(path.read_text())
    return default


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def capture_main(func):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        func()
    return json.loads(out.getvalue())


def safe_name(entry):
    return f"{entry['device'].replace(',', '_')}_{entry['ios']}_{entry['build']}_Restore"


def extracted_dsc(entry):
    base = FIRMWARE / "extracted" / safe_name(entry)
    matches = sorted(base.glob(f"{entry['build']}__*/dyld_shared_cache_arm64e"))
    if len(matches) != 1:
        raise RuntimeError(f"expected one dyld cache under {base}, got {matches}")
    return matches[0]


def extracted_exists(out_dir):
    return any(out_dir.glob("*/dyld_shared_cache_arm64e"))


def extract_remote_dyld(entry):
    out_dir = FIRMWARE / "extracted" / safe_name(entry)
    if extracted_exists(out_dir):
        return extracted_dsc(entry)
    out_dir.mkdir(parents=True, exist_ok=True)
    run([
        "ipsw", "extract",
        "--remote",
        "--dyld",
        "--dyld-arch", "arm64e",
        "--output", str(out_dir),
        entry["url"],
        "--no-color",
    ])
    return extracted_dsc(entry)


def symbol_dump(tag, dsc):
    sym_path = WORK / f"{tag}_symaddr_all.txt"
    pthread_path = WORK / f"{tag}_libsystem_pthread_image.txt"
    with sym_path.open("w") as handle:
        run(["ipsw", "dyld", "symaddr", str(dsc), "--all", "--no-color"], stdout=handle)
    with pthread_path.open("w") as handle:
        run(["ipsw", "dyld", "image", str(dsc), "/usr/lib/system/libsystem_pthread.dylib", "--no-color"], stdout=handle)


def build_reports_for(entry):
    targets = {
        entry["tag"]: {
            "ios": entry["ios"],
            "device_key": entry["device_key"],
            "dsc": Path(entry["dsc"]),
        }
    }
    dsc_targets = {entry["tag"]: Path(entry["dsc"])}

    symbol_build.TARGETS = targets
    symbol_report = capture_main(symbol_build.main)
    tmp_symbol = WORK / ".ios184_batch_symbol_offsets_report.json"
    save_json(tmp_symbol, symbol_report)

    manual_build.REPORT = tmp_symbol
    manual_build.TARGETS = dsc_targets
    manual_report = capture_main(manual_build.main)
    tmp_manual = WORK / ".ios184_batch_manual_offsets_report.json"
    save_json(tmp_manual, manual_report)

    rce_build.SYMBOL_REPORT = tmp_symbol
    rce_build.MANUAL_REPORT = tmp_manual
    rce_build.TARGETS = dsc_targets
    rce_report = capture_main(rce_build.main)

    return symbol_report, manual_report, rce_report


def merge_reports(reports):
    for name, report in zip(("symbol", "manual", "rce"), reports):
        existing = load_json(REPORTS[name], {})
        existing.update(report)
        save_json(REPORTS[name], existing)


def format_entry(key, values):
    lines = [f'   "{key}": {{']
    for name, value in values.items():
        lines.append(f"      {name}: {value},")
    lines.append("   },")
    return "\n".join(lines)


def parse_rce_object(text, device_key):
    match = re.search(rf'"{re.escape(device_key)}"\s*:\s*\{{\n(.*?)\n\s*\}},', text, re.S)
    if not match:
        return None
    values = {}
    for line in match.group(1).splitlines():
        field = re.match(r"\s*([A-Za-z0-9_]+):\s*([^,]+),\s*$", line)
        if field:
            values[field.group(1)] = field.group(2)
    return values


def insert_rce_object(text, device_key, offsets):
    if parse_rce_object(text, device_key) is not None:
        return text
    marker = "rce_offsets = {\n"
    if marker not in text:
        raise RuntimeError("rce_offsets marker not found")
    return text.replace(marker, marker + format_entry(device_key, offsets) + "\n", 1)


def add_linkedit(text, ios, linkedit, device_key, offsets):
    version_key = ios.replace(".", ",")
    pattern = re.compile(rf"('{re.escape(version_key)}': \{{\n)(.*?)(\n\s*\}})", re.S)
    match = pattern.search(text)
    if not match:
        raise RuntimeError(f"linkedit block not found for {version_key}")

    body = match.group(2)
    existing = re.search(rf"\[{re.escape(linkedit)}\]:\s*\"([^\"]+)\"", body)
    if existing:
        existing_key = existing.group(1)
        existing_offsets = parse_rce_object(text, existing_key)
        if existing_key == device_key or existing_offsets == offsets:
            return text
        raise RuntimeError(f"{version_key} {linkedit} maps to non-identical {existing_key} and {device_key}")

    lines = body.splitlines()
    if lines and not lines[-1].rstrip().endswith(","):
        lines[-1] += ","
    lines.append(f'    [{linkedit}]: "{device_key}",')
    return text[:match.start(2)] + "\n".join(lines) + text[match.end(2):]


def add_chipset(text, device_key, group):
    if re.search(rf'"{re.escape(device_key)}"\s*:\s*"[0-9a-f]+"', text):
        return text
    table = re.search(r"const device_chipset = \{(.*?)\n\}", text, re.S)
    if not table:
        raise RuntimeError("device_chipset table not found")
    pairs = dict(re.findall(r'"([^"]+)": "([0-9a-f]+)"', table.group(1)))
    chipset = None
    for key, value in pairs.items():
        if key.rsplit("_", 1)[0] == group:
            chipset = value
            break
    if not chipset:
        raise RuntimeError(f"no chipset hash for {group}")
    marker = "const device_chipset = {\n"
    return text.replace(marker, marker + f'"{device_key}": "{chipset}",\n', 1)


def patch_runtime(entry, rce_report):
    rec = rce_report[entry["tag"]]
    for name in ("rce_module.js", "rce_worker_18.6.js"):
        path = ROOT / name
        text = path.read_text()
        text = insert_rce_object(text, rec["device_key"], rec["offsets"])
        text = add_linkedit(text, rec["ios"], rec["offsets"]["libsystem_pthread_linkedit"], rec["device_key"], rec["offsets"])
        text = add_chipset(text, rec["device_key"], entry["group"])
        path.write_text(text)


def cleanup(entry):
    paths = [
        FIRMWARE / "extracted" / safe_name(entry),
        WORK / f"{entry['tag']}_symaddr_all.txt",
        WORK / f"{entry['tag']}_libsystem_pthread_image.txt",
    ]
    paths.extend(FIRMWARE.glob("ipsw/*.ipsw"))
    paths = [str(path) for path in paths if path.exists()]
    if paths:
        run(["trash", *paths])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--only", nargs="*")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    processed = {rec["device_key"] for rec in load_json(REPORTS["rce"], {}).values()}
    pending = [entry for entry in manifest if entry.get("url") and entry["device_key"] not in processed]
    if args.only:
        wanted = set(args.only)
        pending = [entry for entry in pending if entry["device_key"] in wanted or f"{entry['build']}__{entry['device']}" in wanted]
    batch = pending[: args.limit]
    if not batch:
        print("no pending targets")
        return

    processed_now = []
    for entry in batch:
        entry["tag"] = f"{entry['build']}__{entry['device']}"
        try:
            print(f"extracting {entry['device_key']} from {entry['url']}", flush=True)
            dsc = extract_remote_dyld(entry)
            entry["dsc"] = str(dsc)
            print(f"dumping symbols {entry['tag']}", flush=True)
            symbol_dump(entry["tag"], dsc)

            reports = build_reports_for(entry)
            symbol_report, manual_report, rce_report = reports
            tag = entry["tag"]
            if symbol_report[tag]["missing_symbol_patterns"]:
                raise RuntimeError(f"{tag}: missing symbols {symbol_report[tag]['missing_symbol_patterns']}")
            if len(manual_report[tag]["manual_offsets"]) != 12:
                raise RuntimeError(f"{tag}: manual count mismatch")
            if len(rce_report[tag]["offsets"]) != 105:
                raise RuntimeError(f"{tag}: rce count mismatch")

            patch_runtime(entry, rce_report)
            merge_reports(reports)
            processed_now.append(entry["device_key"])
            print(f"processed: {entry['device_key']}", flush=True)
        finally:
            cleanup(entry)

    print("processed batch:", ", ".join(processed_now))


if __name__ == "__main__":
    sys.exit(main())
