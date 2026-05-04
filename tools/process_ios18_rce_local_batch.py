#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import subprocess
import sys
from pathlib import Path

import build_ios18_rce_offset_candidates as rce_build
import derive_ios18_manual_offsets as manual_build
import extract_ios18_symbol_offsets as symbol_build


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "firmware"
WORK = FIRMWARE / "work"
IPSW_DIR = FIRMWARE / "ipsw"


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


def expected_ipsw_path(entry):
    if entry.get("filename"):
        return IPSW_DIR / entry["filename"]
    return None


def find_ipsw(entry):
    expected = expected_ipsw_path(entry)
    if expected and expected.exists():
        return expected
    matches = sorted(IPSW_DIR.glob(f"*_{entry['ios']}_{entry['build']}_Restore.ipsw"))
    matches = [p for p in matches if entry["device"] in p.name]
    if len(matches) == 1:
        return matches[0]
    return None


def download_ipsw(entry):
    IPSW_DIR.mkdir(parents=True, exist_ok=True)
    existing = find_ipsw(entry)
    if existing:
        return existing
    run([
        "ipsw", "download", "ipsw",
        "--device", entry["device"],
        "--build", entry["build"],
        "--output", str(IPSW_DIR),
        "--confirm",
        "--no-color",
    ])
    found = find_ipsw(entry)
    if not found:
        raise RuntimeError(f"downloaded IPSW not found for {entry['device_key']}")
    return found


def extracted_dsc(entry):
    base = FIRMWARE / "extracted" / safe_name(entry)
    matches = sorted(base.glob(f"{entry['build']}__*/dyld_shared_cache_arm64e"))
    if len(matches) != 1:
        raise RuntimeError(f"expected one dyld cache under {base}, got {matches}")
    return matches[0]


def extract_local_dyld(entry, ipsw_path):
    out_dir = FIRMWARE / "extracted" / safe_name(entry)
    if any(out_dir.glob("*/dyld_shared_cache_arm64e")):
        return extracted_dsc(entry)
    out_dir.mkdir(parents=True, exist_ok=True)
    run([
        "ipsw", "extract",
        "--dyld",
        "--dyld-arch", "arm64e",
        "--output", str(out_dir),
        str(ipsw_path),
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
    if not sym_path.exists() or not pthread_path.exists():
        raise RuntimeError(f"symbol dump outputs missing for {tag}")


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
    tmp_symbol = WORK / ".ios18_rce_local_symbol_offsets_report.json"
    save_json(tmp_symbol, symbol_report)

    manual_build.REPORT = tmp_symbol
    manual_build.TARGETS = dsc_targets
    manual_report = capture_main(manual_build.main)
    tmp_manual = WORK / ".ios18_rce_local_manual_offsets_report.json"
    save_json(tmp_manual, manual_report)

    rce_build.SYMBOL_REPORT = tmp_symbol
    rce_build.MANUAL_REPORT = tmp_manual
    rce_build.TARGETS = dsc_targets
    rce_report = capture_main(rce_build.main)
    return symbol_report, manual_report, rce_report


def cleanup(entry, ipsw_path):
    paths = [
        FIRMWARE / "extracted" / safe_name(entry),
        WORK / f"{entry['tag']}_symaddr_all.txt",
        WORK / f"{entry['tag']}_libsystem_pthread_image.txt",
    ]
    if ipsw_path:
        paths.append(ipsw_path)
    existing = [str(path) for path in paths if path.exists()]
    if existing:
        run(["trash", *existing])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--prefix", default="ios18_rce_local")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--keep-on-error", action="store_true")
    args = parser.parse_args()

    entries = json.loads(Path(args.manifest).read_text())
    if args.only:
        wanted = set(args.only)
        entries = [e for e in entries if e["device_key"] in wanted or f"{e['build']}__{e['device']}" in wanted]
    if args.limit is not None:
        entries = entries[: args.limit]

    reports = {"symbol": {}, "manual": {}, "rce": {}}
    processed = []
    for entry in entries:
        entry["tag"] = f"{entry['build']}__{entry['device']}"
        ipsw_path = None
        ok = False
        try:
            print(f"downloading {entry['device_key']}", flush=True)
            ipsw_path = download_ipsw(entry)
            print(f"extracting {entry['device_key']} from {ipsw_path.name}", flush=True)
            dsc = extract_local_dyld(entry, ipsw_path)
            entry["dsc"] = str(dsc)
            print(f"dumping symbols {entry['tag']}", flush=True)
            symbol_dump(entry["tag"], dsc)
            symbol_report, manual_report, rce_report = build_reports_for(entry)
            tag = entry["tag"]
            checks = {
                "missing_symbols": symbol_report[tag]["missing_symbol_patterns"],
                "manual_count": len(manual_report[tag]["manual_offsets"]),
                "rce_count": len(rce_report[tag]["offsets"]),
            }
            print(f"checks {entry['device_key']}: {checks}", flush=True)
            if checks["missing_symbols"] or checks["manual_count"] != 12 or checks["rce_count"] != 105:
                raise RuntimeError(f"{tag}: failed checks {checks}")
            reports["symbol"].update(symbol_report)
            reports["manual"].update(manual_report)
            reports["rce"].update(rce_report)
            processed.append(entry["device_key"])
            ok = True
        finally:
            if ok or not args.keep_on_error:
                cleanup(entry, ipsw_path)

    save_json(WORK / f"{args.prefix}_symbol_offsets_report.json", reports["symbol"])
    save_json(WORK / f"{args.prefix}_manual_offsets_report.json", reports["manual"])
    save_json(WORK / f"{args.prefix}_rce_offset_candidates.json", reports["rce"])
    print("processed:", ", ".join(processed))


if __name__ == "__main__":
    sys.exit(main())
