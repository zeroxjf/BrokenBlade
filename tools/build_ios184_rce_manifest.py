#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "firmware" / "work"
OUT = WORK / "ios184_rce_target_manifest.json"

BUILD_TO_IOS = {
    "22E240": "18.4",
    "22E252": "18.4.1",
}


def run(args):
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def representative_device(group):
    return group.split("_", 1)[0]


def firmware_url(device, ios):
    proc = run([
        "ipsw",
        "download",
        "ipsw",
        "--device",
        device,
        "--version",
        ios,
        "--urls",
        "--no-color",
    ])
    urls = [line.strip() for line in proc.stdout.splitlines() if line.startswith("http")]
    if len(urls) == 1:
        return urls[0], "ok"
    return "", proc.stdout.strip() or f"exit={proc.returncode}"


def main():
    keys = set()
    for name in ("sbx0_main_18.4.js", "sbx1_main.js"):
        text = (ROOT / name).read_text()
        keys.update(re.findall(r'"(iPhone[^"]+_22E(?:240|252))"\s*:\s*\{', text))

    manifest = []
    for device_key in sorted(keys):
        group, build = device_key.rsplit("_", 1)
        ios = BUILD_TO_IOS[build]
        device = representative_device(group)
        url, status = firmware_url(device, ios)
        manifest.append({
            "build": build,
            "device": device,
            "device_key": device_key,
            "group": group,
            "ios": ios,
            "url": url,
            "url_status": status,
        })

    WORK.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT} ({len(manifest)} targets)")
    missing = [entry["device_key"] for entry in manifest if not entry["url"]]
    if missing:
        print("missing URLs:")
        for key in missing:
            print(f"  {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
