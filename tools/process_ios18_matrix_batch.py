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
import derive_ios18_sbx_offsets as sbx_build
import extract_ios18_symbol_offsets as symbol_build


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "firmware"
WORK = FIRMWARE / "work"
DEFAULT_MANIFEST = WORK / "ios18_remaining_target_manifest.json"

REPORTS = {
    "symbol": WORK / "ios18_matrix_symbol_offsets_report.json",
    "manual": WORK / "ios18_matrix_manual_offsets_report.json",
    "rce": WORK / "ios18_matrix_rce_offset_candidates.json",
    "sbx": WORK / "ios18_matrix_sbx_offsets_report.json",
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


def extracted_exists(out_dir):
    return any(out_dir.glob("*/dyld_shared_cache_arm64e"))


def symbol_dump(tag, dsc):
    sym_path = WORK / f"{tag}_symaddr_all.txt"
    pthread_path = WORK / f"{tag}_libsystem_pthread_image.txt"
    with sym_path.open("w") as handle:
        run(["ipsw", "dyld", "symaddr", str(dsc), "--all", "--no-color"], stdout=handle)
    with pthread_path.open("w") as handle:
        run(["ipsw", "dyld", "image", str(dsc), "/usr/lib/system/libsystem_pthread.dylib", "--no-color"], stdout=handle)


def build_reports_for(entries):
    targets = {
        entry["tag"]: {
            "ios": entry["ios"],
            "device_key": entry["device_key"],
            "dsc": Path(entry["dsc"]),
        }
        for entry in entries
    }
    dsc_targets = {tag: meta["dsc"] for tag, meta in targets.items()}

    symbol_build.TARGETS = targets
    symbol_report = capture_main(symbol_build.main)
    tmp_symbol = WORK / ".ios18_batch_symbol_offsets_report.json"
    save_json(tmp_symbol, symbol_report)

    manual_build.REPORT = tmp_symbol
    manual_build.TARGETS = dsc_targets
    manual_report = capture_main(manual_build.main)
    tmp_manual = WORK / ".ios18_batch_manual_offsets_report.json"
    save_json(tmp_manual, manual_report)

    rce_build.SYMBOL_REPORT = tmp_symbol
    rce_build.MANUAL_REPORT = tmp_manual
    rce_build.TARGETS = dsc_targets
    rce_report = capture_main(rce_build.main)

    sbx_build.SYMBOL_REPORT = tmp_symbol
    sbx_build.MANUAL_REPORT = tmp_manual
    sbx_build.TARGETS = dsc_targets
    sbx_report = capture_main(sbx_build.main)

    return symbol_report, manual_report, rce_report, sbx_report


def merge_reports(new_reports):
    for name, report in zip(("symbol", "manual", "rce", "sbx"), new_reports):
        existing = load_json(REPORTS[name], {})
        existing.update(report)
        save_json(REPORTS[name], existing)


def chipset_map():
    text = (ROOT / "rce_module.js").read_text()
    table = re.search(r"const device_chipset = \{(.*?)\n\}", text, re.S).group(1)
    pairs = dict(re.findall(r'"([^"]+)": "([0-9a-f]+)"', table))
    out = {}
    for key, value in pairs.items():
        model = key.rsplit("_", 1)[0]
        out.setdefault(model, value)
    return out


def format_entry(key, values):
    lines = [f'   "{key}": {{']
    for name, value in values.items():
        lines.append(f"      {name}: {value},")
    lines.append("   },")
    return "\n".join(lines)


def snippet_device_keys(snippet):
    return re.findall(r'^\s*"([^"]+)": \{', snippet, re.M)


def insert_after_marker(text, marker, snippet):
    if all(f'"{key}": {{' in text for key in snippet_device_keys(snippet)):
        return text
    if snippet in text:
        return text
    if marker not in text:
        raise RuntimeError(f"marker not found: {marker!r}")
    return text.replace(marker, marker + snippet + "\n", 1)


def add_linkedit(text, ios, linkedit, device_key):
    version_key = ios.replace(".", ",")
    want = f'    [{linkedit}]: "{device_key}",'
    if want in text:
        return text
    pattern = re.compile(rf"('{re.escape(version_key)}': \{{\n)(.*?)(\n\s*\}})", re.S)
    match = pattern.search(text)
    if not match:
        marker = "const linkedit_to_device = {\n"
        if marker not in text:
            raise RuntimeError(f"linkedit map not found for {version_key}")
        snippet = f"'{version_key}': {{\n{want}\n}},\n"
        return text.replace(marker, marker + snippet, 1)
    lines = match.group(2).splitlines()
    if lines and not lines[-1].rstrip().endswith(","):
        lines[-1] += ","
    lines.append(want)
    return text[:match.start(2)] + "\n".join(lines) + text[match.end(2):]


def add_chipset(text, device_key, chipset):
    want = f'"{device_key}": "{chipset}",'
    if want in text:
        return text
    marker = "const device_chipset = {\n"
    return text.replace(marker, marker + want + "\n", 1)


def patch_runtime(entries, rce_report, sbx_report):
    chips = chipset_map()
    for entry in entries:
        if entry["group"] not in chips:
            raise RuntimeError(f"no existing chipset hash for {entry['group']}")

    rce_snippet = "\n".join(format_entry(rce_report[e["tag"]]["device_key"], rce_report[e["tag"]]["offsets"]) for e in entries)
    sbx0_snippet = "\n".join(format_entry(sbx_report[e["tag"]]["device_key"], sbx_report[e["tag"]]["sbx0_offsets"]) for e in entries)
    sbx1_snippet = "\n".join(format_entry(sbx_report[e["tag"]]["device_key"], sbx_report[e["tag"]]["sbx1_offsets"]) for e in entries)

    for name in ("rce_module.js", "rce_worker_18.6.js", "rce_worker_18.3.js"):
        path = ROOT / name
        text = path.read_text()
        text = insert_after_marker(text, "rce_offsets = {\n", rce_snippet)
        for entry in entries:
            rec = rce_report[entry["tag"]]
            text = add_linkedit(text, rec["ios"], rec["offsets"]["libsystem_pthread_linkedit"], rec["device_key"])
            text = add_chipset(text, rec["device_key"], chips[entry["group"]])
        path.write_text(text)

    for name, marker, snippet in (
        ("sbx0_main_18.4.js", "  sbx0_offsets = {\n", sbx0_snippet),
        ("sbx1_main.js", "    sbx1_offsets = {\n", sbx1_snippet),
    ):
        path = ROOT / name
        text = path.read_text()
        text = insert_after_marker(text, marker, snippet)
        path.write_text(text)


def cleanup(entries):
    paths = []
    for entry in entries:
        paths.append(FIRMWARE / "extracted" / safe_name(entry))
        paths.append(WORK / f"{entry['tag']}_symaddr_all.txt")
        paths.append(WORK / f"{entry['tag']}_libsystem_pthread_image.txt")
    paths.extend(FIRMWARE.glob("ipsw/*.ipsw"))
    paths = [str(path) for path in paths if path.exists()]
    if paths:
        run(["trash", *paths])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    processed = set()
    for path in REPORTS.values():
        for rec in load_json(path, {}).values():
            if isinstance(rec, dict) and "device_key" in rec:
                processed.add(rec["device_key"])

    pending = [entry for entry in manifest if entry.get("url") and (args.force or entry["device_key"] not in processed)]
    if args.only:
        wanted = set(args.only)
        pending = [entry for entry in pending if entry["device_key"] in wanted or entry["tag"] in wanted]
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

            reports = build_reports_for([entry])
            symbol_report, manual_report, rce_report, sbx_report = reports
            tag = entry["tag"]
            if symbol_report[tag]["missing_symbol_patterns"]:
                raise RuntimeError(f"{tag}: missing symbols {symbol_report[tag]['missing_symbol_patterns']}")
            if len(manual_report[tag]["manual_offsets"]) != 12:
                raise RuntimeError(f"{tag}: manual count mismatch")
            if len(rce_report[tag]["offsets"]) != 105:
                raise RuntimeError(f"{tag}: rce count mismatch")
            if len(sbx_report[tag]["sbx0_offsets"]) != 40 or len(sbx_report[tag]["sbx1_offsets"]) != 24:
                raise RuntimeError(f"{tag}: sbx count mismatch")

            patch_runtime([entry], rce_report, sbx_report)
            merge_reports(reports)
            processed_now.append(entry["device_key"])
            print(f"processed: {entry['device_key']}", flush=True)
        finally:
            cleanup([entry])

    print("processed batch:", ", ".join(processed_now))


if __name__ == "__main__":
    sys.exit(main())
